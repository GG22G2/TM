import {Trans} from "../trans"

function getUTCDateStr(now) {
    var y = now.getUTCFullYear(),
        m = now.getUTCMonth() + 1,
        d = now.getUTCDate();
    return y + "-" + (m < 10 ? "0" + m : m) + "-" + (d < 10 ? "0" + d : d);
}

//字符串转为字节输入
const getUtf8Bytes = msg =>
    new Uint8Array(
        [...unescape(encodeURIComponent(msg))].map(c => c.charCodeAt(0))
    );

/**
 *
 * */
async function HMAC_SHA256(keyBuffer, msg) {

    const messageBuffer = getUtf8Bytes(msg);
    const cryptoKey = await crypto.subtle.importKey(
        "raw", keyBuffer, {name: "HMAC", hash: {name: "SHA-256"}},
        true, ["sign"]
    );

    let hashArray = await window.crypto.subtle.sign(
        "HMAC",
        cryptoKey,
        messageBuffer
    );
    return hashArray;
}

function HexEncode(hashBuffer) {
    const hashArray = Array.from(new Uint8Array(hashBuffer));                     // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
    return hashHex;
}

async function SHA256(str) {
    const msgUint8 = new TextEncoder().encode(str);                           // encode as (utf-8) Uint8Array
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);           // hash the message
    return hashBuffer;
}


/**
 * payload : json请求体
 * timeStamp 当前时区时间戳 精确到秒
 * dateStr 年月日 utc时区
 * SecretKey
 * */
async function calSignature(payload, timeStamp, dateStr, SecretKey) {
    // 拼接规范请求串过程
    let HTTPRequestMethod = "POST";
    let CanonicalURI = '/';
    let CanonicalQueryString = '';
    let CanonicalHeaders = 'content-type:application/json\nhost:tmt.tencentcloudapi.com\n';
    let SignedHeaders = 'content-type;host';

    //Lowercase(HexEncode(Hash.SHA256(RequestPayload))) 根据payload 生成HashedRequestPayload。 做SHA256哈希，然后十六进制编码，最后编码串转换成小写字母
    let HashedRequestPayload = HexEncode(await SHA256(JSON.stringify(payload))).toLowerCase();

    //规范请求串
    let CanonicalRequest = HTTPRequestMethod + '\n' + CanonicalURI + '\n' + CanonicalQueryString + '\n' + CanonicalHeaders + '\n' + SignedHeaders + '\n' + HashedRequestPayload;

    // 拼接待签名字符串过程
    // Lowercase(HexEncode(Hash.SHA256(CanonicalRequest)))
    let HashedCanonicalRequest = HexEncode(await SHA256(CanonicalRequest)).toLowerCase();

    let StringToSign = 'TC3-HMAC-SHA256\n' + timeStamp + '\n' + dateStr + '/tmt/tc3_request\n' + HashedCanonicalRequest

    let SecretDate = await HMAC_SHA256(getUtf8Bytes("TC3" + SecretKey), dateStr)
    let SecretService = await HMAC_SHA256(SecretDate, 'tmt')
    let SecretSigning = await HMAC_SHA256(SecretService, "tc3_request")
    let Signature = HexEncode(await HMAC_SHA256(SecretSigning, StringToSign))
    return Signature;
}


//腾讯翻译
export var tencentTrans = {
    code: "tc",
    codeText: "腾讯",
    SecretId: '',
    SecretKey: '',
    defaultOrigLang: "auto",         //默认源语言
    defaultTargetLang: "zh",         //默认目标语言
    langList: {"auto": "自动检测", "zh": "中文", "cht": "繁体中文", "en": "英语"},
    Execute: async function (h_onloadfn) {
        var self = this;
        let date = new Date();
        let utcDateStr = getUTCDateStr(date);
        // 当前系统时间，且需确保系统时间和标准时间是同步的，取当前时间 UNIX 时间戳，精确到秒
        let dateTime = date.getTime() / 1000 | 0;
        var datas = {
            SourceText: Trans.transText != null ? Trans.transText : 'hello',
            Source: 'auto',
            Target: 'zh',
            ProjectId: 0,
        };
        let Signature = await calSignature(datas, dateTime, utcDateStr, this.SecretKey);
        let Authorization = 'TC3-HMAC-SHA256 Credential=' + this.SecretId + '/' + utcDateStr + '/tmt/tc3_request, SignedHeaders=content-type;host, Signature=' + Signature;

        GM_xmlhttpRequest({
            method: "POST",
            headers: {
                "Host": 'tmt.tencentcloudapi.com',
                "Content-Type": 'application/json',
                "X-TC-Action": 'TextTranslate',
                "X-TC-Timestamp": dateTime,
                "X-TC-Version": '2018-03-21',
                "Authorization": Authorization,
                "X-TC-Region": 'ap-shanghai',
                "X-TC-Language": 'zh-CN',
            },
            url: "https://tmt.tencentcloudapi.com",
            data: JSON.stringify(datas),
            onload: function (r) {
                var data = JSON.parse(r.responseText).Response;
                console.log(r)
                console.log(data)

                Trans.transResult.orig = [Trans.transText];
                if (data.Error != null) { //报错
                    Trans.transResult.trans = ['翻译接口出错: ' + data.Error.Message];
                    Trans.transResult.origLang = 'auto';
                } else if (data.TargetText != null) {
                    Trans.transResult.trans = [data.TargetText];
                    Trans.transResult.origLang = data.Source;
                }

                h_onloadfn();
            },
            onerror: function (e) {
                console.error(e);
            }
        });
    },
    init: function () {
        //初始化 SecretId和SecretKey，需要从腾讯云获取
        this.SecretId = 'a';
        this.SecretKey = 'a';
    }
}
