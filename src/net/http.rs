//! # HTTP module.

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use mime::Mime;
use serde::Serialize;
use tokio::fs;

use crate::blob::BlobObject;
use crate::context::Context;
use crate::log::warn;
use crate::net::proxy::ProxyConfig;
use crate::net::session::SessionStream;
use crate::net::tls::wrap_rustls;
use crate::tools::time;

/// User-Agent for HTTP requests if a resource usage policy requires it.
/// By default we do not set User-Agent.
const USER_AGENT: &str = "chatmail/2 (+https://github.com/chatmail/core/)";

/// HTTP(S) GET response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Response body.
    pub blob: Vec<u8>,

    /// MIME type extracted from the `Content-Type` header, if any.
    pub mimetype: Option<String>,

    /// Encoding extracted from the `Content-Type` header, if any.
    pub encoding: Option<String>,
}

/// Retrieves the text contents of URL using HTTP GET request.
pub async fn read_url(context: &Context, url: &str) -> Result<String> {
    let response = read_url_blob(context, url).await?;
    let text = String::from_utf8_lossy(&response.blob);
    Ok(text.to_string())
}

async fn get_http_sender<B>(
    context: &Context,
    parsed_url: hyper::Uri,
) -> Result<hyper::client::conn::http1::SendRequest<B>>
where
    B: hyper::body::Body + 'static + Send,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let scheme = parsed_url.scheme_str().context("URL has no scheme")?;
    let host = parsed_url.host().context("URL has no host")?;
    let proxy_config_opt = ProxyConfig::load(context).await?;

    let stream: Box<dyn SessionStream> = match scheme {
        "http" => {
            let port = parsed_url.port_u16().unwrap_or(80);

            // It is safe to use cached IP addresses
            // for HTTPS URLs, but for HTTP URLs
            // better resolve from scratch each time to prevent
            // cache poisoning attacks from having lasting effects.
            let load_cache = false;
            if let Some(proxy_config) = proxy_config_opt {
                let proxy_stream = proxy_config
                    .connect(context, host, port, load_cache)
                    .await?;
                Box::new(proxy_stream)
            } else {
                let tcp_stream = crate::net::connect_tcp(context, host, port, load_cache).await?;
                Box::new(tcp_stream)
            }
        }
        "https" => {
            let port = parsed_url.port_u16().unwrap_or(443);
            let (use_sni, load_cache) = (true, true);

            if let Some(proxy_config) = proxy_config_opt {
                let proxy_stream = proxy_config
                    .connect(context, host, port, load_cache)
                    .await?;
                let tls_stream = wrap_rustls(
                    host,
                    port,
                    use_sni,
                    "",
                    proxy_stream,
                    &context.tls_session_store,
                )
                .await?;
                Box::new(tls_stream)
            } else {
                let tcp_stream = crate::net::connect_tcp(context, host, port, load_cache).await?;
                let tls_stream = wrap_rustls(
                    host,
                    port,
                    use_sni,
                    "",
                    tcp_stream,
                    &context.tls_session_store,
                )
                .await?;
                Box::new(tls_stream)
            }
        }
        _ => bail!("Unknown URL scheme"),
    };

    let io = TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(conn);

    Ok(sender)
}

/// Converts the URL to expiration and stale timestamps.
#[expect(clippy::arithmetic_side_effects)]
fn http_url_cache_timestamps(url: &str, mimetype: Option<&str>) -> (i64, i64) {
    let now = time();

    let expires = now + 3600 * 24 * 35;
    let stale = if url.ends_with(".xdc") {
        // WebXDCs are never stale, they just expire.
        expires
    } else if url.starts_with("https://tile.openstreetmap.org/")
        || url.starts_with("https://vector.openstreetmap.org/")
    {
        // Policy at <https://operations.osmfoundation.org/policies/tiles/>
        // requires that we cache tiles for at least 7 days.
        // Do not revalidate earlier than that.
        now + 3600 * 24 * 7
    } else if mimetype.is_some_and(|s| s.starts_with("image/")) {
        // Cache images for 1 day.
        //
        // As of 2024-12-12 WebXDC icons at <https://webxdc.org/apps/>
        // use the same path for all app versions,
        // so may change, but it is not critical if outdated icon is displayed.
        now + 3600 * 24
    } else {
        // Revalidate everything else after 1 hour.
        //
        // This includes HTML, CSS and JS.
        now + 3600
    };
    (expires, stale)
}

/// Places the binary into HTTP cache.
async fn http_cache_put(context: &Context, url: &str, response: &Response) -> Result<()> {
    let blob =
        BlobObject::create_and_deduplicate_from_bytes(context, response.blob.as_slice(), "")?;

    let (expires, stale) = http_url_cache_timestamps(url, response.mimetype.as_deref());
    context
        .sql
        .insert(
            "INSERT OR REPLACE INTO http_cache (url, expires, stale, blobname, mimetype, encoding)
             VALUES (?, ?, ?, ?, ?, ?)",
            (
                url,
                expires,
                stale,
                blob.as_name(),
                response.mimetype.as_deref().unwrap_or_default(),
                response.encoding.as_deref().unwrap_or_default(),
            ),
        )
        .await?;

    Ok(())
}

/// Retrieves the binary from HTTP cache.
///
/// Also returns if the response is stale and should be revalidated in the background.
#[expect(clippy::arithmetic_side_effects)]
async fn http_cache_get(context: &Context, url: &str) -> Result<Option<(Response, bool)>> {
    let now = time();
    let Some((blob_name, mimetype, encoding, stale_timestamp)) = context
        .sql
        .query_row_optional(
            "SELECT blobname, mimetype, encoding, stale
             FROM http_cache WHERE url=? AND expires > ?",
            (url, now),
            |row| {
                let blob_name: String = row.get(0)?;
                let mimetype: Option<String> = Some(row.get(1)?).filter(|s: &String| !s.is_empty());
                let encoding: Option<String> = Some(row.get(2)?).filter(|s: &String| !s.is_empty());
                let stale_timestamp: i64 = row.get(3)?;
                Ok((blob_name, mimetype, encoding, stale_timestamp))
            },
        )
        .await?
    else {
        return Ok(None);
    };
    let is_stale = now > stale_timestamp;

    let blob_object = BlobObject::from_name(context, &blob_name)?;
    let blob_abs_path = blob_object.to_abs_path();
    let blob = match fs::read(blob_abs_path)
        .await
        .with_context(|| format!("Failed to read blob for {url:?} cache entry."))
    {
        Ok(blob) => blob,
        Err(err) => {
            // This should not happen, but user may go into the blobdir and remove files,
            // antivirus may delete the file or there may be a bug in housekeeping.
            warn!(context, "{err:?}.");
            return Ok(None);
        }
    };

    let (expires, _stale) = http_url_cache_timestamps(url, mimetype.as_deref());
    let response = Response {
        blob,
        mimetype,
        encoding,
    };

    // Update expiration timestamp
    // to prevent deletion of the file still in use.
    //
    // If the response is stale, the caller should revalidate it in the background, so update
    // `stale` timestamp to avoid revalidating too frequently (and have many parallel revalidation
    // tasks) if revalidation fails or the HTTP request takes some time. The stale period >= 1 hour,
    // so 1 more minute won't be a problem.
    let stale_timestamp = if is_stale { now + 60 } else { stale_timestamp };
    context
        .sql
        .execute(
            "UPDATE http_cache SET expires=?, stale=? WHERE url=?",
            (expires, stale_timestamp, url),
        )
        .await?;

    Ok(Some((response, is_stale)))
}

/// Removes expired cache entries.
pub(crate) async fn http_cache_cleanup(context: &Context) -> Result<()> {
    // Remove cache entries that are already expired
    // or entries that will not expire in a year
    // to make sure we don't have invalid timestamps that are way forward in the future.
    context
        .sql
        .execute(
            "DELETE FROM http_cache
             WHERE ?1 > expires OR expires > ?1 + 31536000",
            (time(),),
        )
        .await?;
    Ok(())
}

/// Fetches URL and updates the cache.
///
/// URL is fetched regardless of whether there is an existing result in the cache.
async fn fetch_url(context: &Context, original_url: &str) -> Result<Response> {
    let mut url = original_url.to_string();

    // Follow up to 10 http-redirects
    for _i in 0..10 {
        let parsed_url = url
            .parse::<hyper::Uri>()
            .with_context(|| format!("Failed to parse URL {url:?}"))?;

        let mut sender = get_http_sender(context, parsed_url.clone()).await?;
        let authority = parsed_url
            .authority()
            .context("URL has no authority")?
            .clone();

        let req = hyper::Request::builder().uri(parsed_url);

        // OSM usage policy requires
        // that User-Agent is set for HTTP GET requests
        // to tile servers:
        // <https://operations.osmfoundation.org/policies/tiles/>
        // Same for vectory tiles
        // at <https://operations.osmfoundation.org/policies/vector/>.
        let req =
            if authority == "tile.openstreetmap.org" || authority == "vector.openstreetmap.org" {
                req.header("User-Agent", USER_AGENT)
            } else {
                req
            };

        let req = req
            .header(hyper::header::HOST, authority.as_str())
            .body(http_body_util::Empty::<Bytes>::new())?;
        let response = sender.send_request(req).await?;

        if response.status().is_redirection() {
            let header = response
                .headers()
                .get_all("location")
                .iter()
                .next_back()
                .ok_or_else(|| anyhow!("Redirection doesn't have a target location"))?
                .to_str()?;
            info!(context, "Following redirect to {}", header);
            url = header.to_string();
            continue;
        }

        if !response.status().is_success() {
            return Err(anyhow!(
                "The server returned a non-successful response code: {}{}",
                response.status().as_u16(),
                response
                    .status()
                    .canonical_reason()
                    .map(|s| format!(" {s}"))
                    .unwrap_or("".to_string())
            ));
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Mime>().ok());
        let mimetype = content_type
            .as_ref()
            .map(|mime| mime.essence_str().to_string());
        let encoding = content_type.as_ref().and_then(|mime| {
            mime.get_param(mime::CHARSET)
                .map(|charset| charset.as_str().to_string())
        });
        let body = response.collect().await?.to_bytes();
        let blob: Vec<u8> = body.to_vec();
        let response = Response {
            blob,
            mimetype,
            encoding,
        };
        info!(context, "Inserting {original_url:?} into cache.");
        http_cache_put(context, &url, &response).await?;
        return Ok(response);
    }

    Err(anyhow!("Followed 10 redirections"))
}

/// Retrieves the binary contents of URL using HTTP GET request.
pub async fn read_url_blob(context: &Context, url: &str) -> Result<Response> {
    if let Some((response, is_stale)) = http_cache_get(context, url).await? {
        info!(context, "Returning {url:?} from cache.");
        if is_stale {
            let context = context.clone();
            let url = url.to_string();
            tokio::spawn(async move {
                // Fetch URL in background to update the cache.
                info!(context, "Fetching stale {url:?} in background.");
                if let Err(err) = fetch_url(&context, &url).await {
                    warn!(context, "Failed to revalidate {url:?}: {err:#}.");
                }
            });
        }
        return Ok(response);
    }

    info!(context, "Not found {url:?} in cache, fetching.");
    let response = fetch_url(context, url).await?;
    Ok(response)
}

/// Sends an empty POST request to the URL.
///
/// Returns response text and whether request was successful or not.
///
/// Does not follow redirects.
pub(crate) async fn post_empty(context: &Context, url: &str) -> Result<(String, bool)> {
    let parsed_url = url
        .parse::<hyper::Uri>()
        .with_context(|| format!("Failed to parse URL {url:?}"))?;
    let scheme = parsed_url.scheme_str().context("URL has no scheme")?;
    if scheme != "https" {
        bail!("POST requests to non-HTTPS URLs are not allowed");
    }

    let mut sender = get_http_sender(context, parsed_url.clone()).await?;
    let authority = parsed_url
        .authority()
        .context("URL has no authority")?
        .clone();
    let req = hyper::Request::post(parsed_url)
        .header(hyper::header::HOST, authority.as_str())
        .body(http_body_util::Empty::<Bytes>::new())?;

    let response = sender.send_request(req).await?;

    let response_status = response.status();
    let body = response.collect().await?.to_bytes();
    let text = String::from_utf8_lossy(&body);
    let response_text = text.to_string();

    Ok((response_text, response_status.is_success()))
}

/// Posts string to the given URL.
///
/// Returns true if successful HTTP response code was returned.
///
/// Does not follow redirects.
#[allow(dead_code)]
pub(crate) async fn post_string(context: &Context, url: &str, body: String) -> Result<bool> {
    let parsed_url = url
        .parse::<hyper::Uri>()
        .with_context(|| format!("Failed to parse URL {url:?}"))?;
    let scheme = parsed_url.scheme_str().context("URL has no scheme")?;
    if scheme != "https" {
        bail!("POST requests to non-HTTPS URLs are not allowed");
    }

    let mut sender = get_http_sender(context, parsed_url.clone()).await?;
    let authority = parsed_url
        .authority()
        .context("URL has no authority")?
        .clone();

    let request = hyper::Request::post(parsed_url)
        .header(hyper::header::HOST, authority.as_str())
        .body(body)?;
    let response = sender.send_request(request).await?;

    Ok(response.status().is_success())
}

/// Sends a POST request with x-www-form-urlencoded data.
///
/// Does not follow redirects.
pub(crate) async fn post_form<T: Serialize + ?Sized>(
    context: &Context,
    url: &str,
    form: &T,
) -> Result<Bytes> {
    let parsed_url = url
        .parse::<hyper::Uri>()
        .with_context(|| format!("Failed to parse URL {url:?}"))?;
    let scheme = parsed_url.scheme_str().context("URL has no scheme")?;
    if scheme != "https" {
        bail!("POST requests to non-HTTPS URLs are not allowed");
    }

    let encoded_body = serde_urlencoded::to_string(form).context("Failed to encode data")?;
    let mut sender = get_http_sender(context, parsed_url.clone()).await?;
    let authority = parsed_url
        .authority()
        .context("URL has no authority")?
        .clone();
    let request = hyper::Request::post(parsed_url)
        .header(hyper::header::HOST, authority.as_str())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(encoded_body)?;
    let response = sender.send_request(request).await?;
    let bytes = response.collect().await?.to_bytes();
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::sql::housekeeping;
    use crate::test_utils::TestContext;
    use crate::tools::SystemTime;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_cache() -> Result<()> {
        let t = &TestContext::new().await;

        assert_eq!(http_cache_get(t, "https://webxdc.org/").await?, None);

        let html_response = Response {
            blob: b"<!DOCTYPE html> ...".to_vec(),
            mimetype: Some("text/html".to_string()),
            encoding: None,
        };

        let xdc_response = Response {
            blob: b"PK...".to_vec(),
            mimetype: Some("application/octet-stream".to_string()),
            encoding: None,
        };
        let xdc_editor_url = "https://apps.testrun.org/webxdc-editor-v3.2.0.xdc";
        let xdc_pixel_url = "https://apps.testrun.org/webxdc-pixel-v2.xdc";

        http_cache_put(t, "https://webxdc.org/", &html_response).await?;

        assert_eq!(http_cache_get(t, xdc_editor_url).await?, None);
        assert_eq!(http_cache_get(t, xdc_pixel_url).await?, None);
        assert_eq!(
            http_cache_get(t, "https://webxdc.org/").await?,
            Some((html_response.clone(), false))
        );

        http_cache_put(t, xdc_editor_url, &xdc_response).await?;
        http_cache_put(t, xdc_pixel_url, &xdc_response).await?;
        assert_eq!(
            http_cache_get(t, xdc_editor_url).await?,
            Some((xdc_response.clone(), false))
        );
        assert_eq!(
            http_cache_get(t, xdc_pixel_url).await?,
            Some((xdc_response.clone(), false))
        );

        assert_eq!(
            http_cache_get(t, "https://webxdc.org/").await?,
            Some((html_response.clone(), false))
        );

        // HTML is stale after 1 hour, but .xdc is not.
        SystemTime::shift(Duration::from_secs(3600 + 100));
        assert_eq!(
            http_cache_get(t, "https://webxdc.org/").await?,
            Some((html_response.clone(), true))
        );
        assert_eq!(
            http_cache_get(t, xdc_editor_url).await?,
            Some((xdc_response.clone(), false))
        );

        // Stale cache entry can be renewed
        // even before housekeeping removes old one.
        http_cache_put(t, "https://webxdc.org/", &html_response).await?;
        assert_eq!(
            http_cache_get(t, "https://webxdc.org/").await?,
            Some((html_response.clone(), false))
        );

        // 35 days later pixel .xdc expires because we did not request it for 35 days and 1 hour.
        // But editor is still there because we did not request it for just 35 days.
        // We have not renewed the editor however, so it becomes stale.
        SystemTime::shift(Duration::from_secs(3600 * 24 * 35 - 100));

        // Run housekeeping to test that it does not delete the blob too early.
        housekeeping(t).await?;

        assert_eq!(
            http_cache_get(t, xdc_editor_url).await?,
            Some((xdc_response.clone(), true))
        );
        assert_eq!(http_cache_get(t, xdc_pixel_url).await?, None);

        // If we get the blob the second time quickly, it shouldn't be stale because it's supposed
        // that we've already run a revalidation task which will update the blob soon.
        assert_eq!(
            http_cache_get(t, xdc_editor_url).await?,
            Some((xdc_response.clone(), false))
        );
        // But if the revalidation task hasn't succeeded after some time, the blob is stale again
        // even if we continue to get it frequently.
        for i in (0..100).rev() {
            SystemTime::shift(Duration::from_secs(6));
            if let Some((_, true)) = http_cache_get(t, xdc_editor_url).await? {
                break;
            }
            assert!(i > 0);
        }

        // Test that if the file is accidentally removed from the blobdir,
        // there is no error when trying to load the cache entry.
        for entry in std::fs::read_dir(t.get_blobdir())? {
            let entry = entry.unwrap();
            let path = entry.path();
            std::fs::remove_file(path).expect("Failed to remove blob");
        }

        assert_eq!(
            http_cache_get(t, xdc_editor_url)
                .await
                .context("Failed to get no cache response")?,
            None
        );

        Ok(())
    }
}
