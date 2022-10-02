// AUTO-GENERATED by typescript-type-def

export type U32=number;
export type Account=(({"type":"Configured";}&{"id":U32;"displayName":(string|null);"addr":(string|null);"profileImage":(string|null);"color":string;})|({"type":"Unconfigured";}&{"id":U32;}));
export type ProviderInfo={"beforeLoginHint":string;"overviewPage":string;"status":U32;};
export type Qr=(({"type":"askVerifyContact";}&{"contact_id":U32;"fingerprint":string;"invitenumber":string;"authcode":string;})|({"type":"askVerifyGroup";}&{"grpname":string;"grpid":string;"contact_id":U32;"fingerprint":string;"invitenumber":string;"authcode":string;})|({"type":"fprOk";}&{"contact_id":U32;})|({"type":"fprMismatch";}&{"contact_id":(U32|null);})|({"type":"fprWithoutAddr";}&{"fingerprint":string;})|({"type":"account";}&{"domain":string;})|({"type":"webrtcInstance";}&{"domain":string;"instance_pattern":string;})|({"type":"addr";}&{"contact_id":U32;"draft":(string|null);})|({"type":"url";}&{"url":string;})|({"type":"text";}&{"text":string;})|({"type":"withdrawVerifyContact";}&{"contact_id":U32;"fingerprint":string;"invitenumber":string;"authcode":string;})|({"type":"withdrawVerifyGroup";}&{"grpname":string;"grpid":string;"contact_id":U32;"fingerprint":string;"invitenumber":string;"authcode":string;})|({"type":"reviveVerifyContact";}&{"contact_id":U32;"fingerprint":string;"invitenumber":string;"authcode":string;})|({"type":"reviveVerifyGroup";}&{"grpname":string;"grpid":string;"contact_id":U32;"fingerprint":string;"invitenumber":string;"authcode":string;})|({"type":"login";}&{"address":string;}));
export type Usize=number;
export type ChatListEntry=[U32,U32];
export type I64=number;
export type ChatListItemFetchResult=(({"type":"ChatListItem";}&{"id":U32;"name":string;"avatarPath":(string|null);"color":string;"lastUpdated":(I64|null);"summaryText1":string;"summaryText2":string;"summaryStatus":U32;"isProtected":boolean;"isGroup":boolean;"freshMessageCounter":Usize;"isSelfTalk":boolean;"isDeviceTalk":boolean;"isSendingLocation":boolean;"isSelfInGroup":boolean;"isArchived":boolean;"isPinned":boolean;"isMuted":boolean;"isContactRequest":boolean;
/**
 * true when chat is a broadcastlist
 */
"isBroadcast":boolean;
/**
 * contact id if this is a dm chat (for view profile entry in context menu)
 */
"dmChatContact":(U32|null);"wasSeenRecently":boolean;})|{"type":"ArchiveLink";}|({"type":"Error";}&{"id":U32;"error":string;}));
export type Contact={"address":string;"color":string;"authName":string;"status":string;"displayName":string;"id":U32;"name":string;"profileImage":(string|null);"nameAndAddr":string;"isBlocked":boolean;"isVerified":boolean;
/**
 * the contact's last seen timestamp
 */
"lastSeen":I64;"wasSeenRecently":boolean;};
export type FullChat={"id":U32;"name":string;"isProtected":boolean;"profileImage":(string|null);"archived":boolean;"chatType":U32;"isUnpromoted":boolean;"isSelfTalk":boolean;"contacts":(Contact)[];"contactIds":(U32)[];"color":string;"freshMessageCounter":Usize;"isContactRequest":boolean;"isDeviceChat":boolean;"selfInGroup":boolean;"isMuted":boolean;"ephemeralTimer":U32;"canSend":boolean;"wasSeenRecently":boolean;"mailingListAddress":string;};

/**
 * cheaper version of fullchat, omits:
 * - contacts
 * - contact_ids
 * - fresh_message_counter
 * - ephemeral_timer
 * - self_in_group
 * - was_seen_recently
 * - can_send
 * 
 * used when you only need the basic metadata of a chat like type, name, profile picture
 */
export type BasicChat=
/**
 * cheaper version of fullchat, omits:
 * - contacts
 * - contact_ids
 * - fresh_message_counter
 * - ephemeral_timer
 * - self_in_group
 * - was_seen_recently
 * - can_send
 * 
 * used when you only need the basic metadata of a chat like type, name, profile picture
 */
{"id":U32;"name":string;"isProtected":boolean;"profileImage":(string|null);"archived":boolean;"chatType":U32;"isUnpromoted":boolean;"isSelfTalk":boolean;"color":string;"isContactRequest":boolean;"isDeviceChat":boolean;"isMuted":boolean;};
export type MuteDuration=("NotMuted"|"Forever"|{"Until":I64;});
export type MessageQuote=(({"kind":"JustText";}&{"text":string;})|({"kind":"WithMessage";}&{"text":string;"messageId":U32;"authorDisplayName":string;"authorDisplayColor":string;"overrideSenderName":(string|null);"image":(string|null);"isForwarded":boolean;}));
export type Viewtype=("Unknown"|
/**
 * Text message.
 */
"Text"|
/**
 * Image message.
 * If the image is an animated GIF, the type `Viewtype.Gif` should be used.
 */
"Image"|
/**
 * Animated GIF message.
 */
"Gif"|
/**
 * Message containing a sticker, similar to image.
 * If possible, the ui should display the image without borders in a transparent way.
 * A click on a sticker will offer to install the sticker set in some future.
 */
"Sticker"|
/**
 * Message containing an Audio file.
 */
"Audio"|
/**
 * A voice message that was directly recorded by the user.
 * For all other audio messages, the type `Viewtype.Audio` should be used.
 */
"Voice"|
/**
 * Video messages.
 */
"Video"|
/**
 * Message containing any file, eg. a PDF.
 */
"File"|
/**
 * Message is an invitation to a videochat.
 */
"VideochatInvitation"|
/**
 * Message is an webxdc instance.
 */
"Webxdc");
export type I32=number;
export type U64=number;
export type WebxdcMessageInfo={
/**
 * The name of the app.
 * 
 * Defaults to the filename if not set in the manifest.
 */
"name":string;
/**
 * App icon file name.
 * Defaults to an standard icon if nothing is set in the manifest.
 * 
 * To get the file, use dc_msg_get_webxdc_blob(). (not yet in jsonrpc, use rust api or cffi for it)
 * 
 * App icons should should be square,
 * the implementations will add round corners etc. as needed.
 */
"icon":string;
/**
 * if the Webxdc represents a document, then this is the name of the document
 */
"document":(string|null);
/**
 * short string describing the state of the app,
 * sth. as "2 votes", "Highscore: 123",
 * can be changed by the apps
 */
"summary":(string|null);
/**
 * URL where the source code of the Webxdc and other information can be found;
 * defaults to an empty string.
 * Implementations may offer an menu or a button to open this URL.
 */
"sourceCodeUrl":(string|null);
/**
 * True if full internet access should be granted to the app.
 */
"internetAccess":boolean;};
export type DownloadState=("Done"|"Available"|"Failure"|"InProgress");
export type Message={"id":U32;"chatId":U32;"fromId":U32;"quote":(MessageQuote|null);"parentId":(U32|null);"text":(string|null);"hasLocation":boolean;"hasHtml":boolean;"viewType":Viewtype;"state":U32;"timestamp":I64;"sortTimestamp":I64;"receivedTimestamp":I64;"hasDeviatingTimestamp":boolean;"subject":string;"showPadlock":boolean;"isSetupmessage":boolean;"isInfo":boolean;"isForwarded":boolean;"duration":I32;"dimensionsHeight":I32;"dimensionsWidth":I32;"videochatType":(U32|null);"videochatUrl":(string|null);"overrideSenderName":(string|null);"sender":Contact;"setupCodeBegin":(string|null);"file":(string|null);"fileMime":(string|null);"fileBytes":U64;"fileName":(string|null);"webxdcInfo":(WebxdcMessageInfo|null);"downloadState":DownloadState;};
export type MessageNotificationInfo={"id":U32;"chatId":U32;"accountId":U32;"image":(string|null);"imageMimeType":(string|null);"chatName":string;"chatProfileImage":(string|null);
/**
 * also known as summary_text1
 */
"summaryPrefix":(string|null);
/**
 * also known as summary_text2
 */
"summaryText":string;};
export type MessageSearchResult={"id":U32;"authorProfileImage":(string|null);"authorName":string;"authorColor":string;"chatName":(string|null);"message":string;"timestamp":I64;};
export type F64=number;
export type __AllTyps=[string,boolean,Record<string,string>,U32,U32,null,(U32)[],U32,null,(U32|null),(Account)[],U32,Account,U32,string,(ProviderInfo|null),U32,boolean,U32,Record<string,string>,U32,string,(string|null),null,U32,Record<string,(string|null)>,null,U32,string,null,U32,string,Qr,U32,string,(string|null),U32,(string)[],Record<string,(string|null)>,U32,null,U32,null,U32,(U32)[],U32,U32,Usize,U32,string,U32,U32,string,null,U32,(U32|null),(string|null),(U32|null),(ChatListEntry)[],U32,(ChatListEntry)[],Record<U32,ChatListItemFetchResult>,U32,U32,FullChat,U32,U32,BasicChat,U32,U32,null,U32,U32,null,U32,U32,null,U32,U32,string,U32,(U32|null),[string,string],U32,U32,null,U32,U32,U32,null,U32,U32,U32,null,U32,U32,(U32)[],U32,string,boolean,U32,U32,U32,U32,U32,string,null,U32,U32,(string|null),null,U32,string,string,U32,U32,U32,null,U32,U32,(U32|null),U32,U32,MuteDuration,null,U32,U32,boolean,U32,(U32)[],null,U32,U32,U32,(U32)[],U32,U32,Message,U32,(U32)[],Record<U32,Message>,U32,U32,MessageNotificationInfo,U32,(U32)[],null,U32,U32,string,U32,U32,null,U32,string,(U32|null),(U32)[],U32,(U32)[],(MessageSearchResult)[],U32,U32,Contact,U32,string,(string|null),U32,U32,U32,U32,U32,U32,null,U32,U32,null,U32,(Contact)[],U32,U32,(string|null),(U32)[],U32,U32,(string|null),(Contact)[],U32,(U32)[],Record<U32,Contact>,U32,U32,string,U32,string,(U32|null),U32,(U32|null),Viewtype,(Viewtype|null),(Viewtype|null),(U32)[],U32,U32,Viewtype,(Viewtype|null),(Viewtype|null),[(U32|null),(U32|null)],null,U32,U32,U32,string,U32,U32,string,string,null,U32,U32,U32,string,U32,U32,WebxdcMessageInfo,U32,(U32)[],U32,null,U32,U32,null,U32,U32,(Message|null),U32,U32,U32,U32,string,U32,U32,U32,U32,(string|null),(string|null),([F64,F64]|null),(U32|null),[U32,Message],U32,U32,(string|null),(string|null),(U32|null),null];
