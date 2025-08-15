use deltachat::net::HttpResponse as CoreHttpResponse;
use serde::Serialize;
use typescript_type_def::TypeDef;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
pub struct HttpResponse {
    /// base64-encoded response body.
    blob: String,

    /// MIME type, e.g. "text/plain" or "text/html".
    mimetype: Option<String>,

    /// Encoding, e.g. "utf-8".
    encoding: Option<String>,
}

impl From<CoreHttpResponse> for HttpResponse {
    fn from(response: CoreHttpResponse) -> Self {
        use base64::{engine::general_purpose, Engine as _};
        let blob = general_purpose::STANDARD_NO_PAD.encode(response.blob);
        let mimetype = response.mimetype;
        let encoding = response.encoding;
        HttpResponse {
            blob,
            mimetype,
            encoding,
        }
    }
}
