# wx_demo
# 微信授权和JS-SDK网页授权
## 开发前配置
> 微信公众平台
- 地址：https://mp.weixin.qq.com/
- 在公众平台的基本设置中获取appid和appsecret，对自己服务器的ip设置白名单
- 在公众号平台需要配置
![image](http://media.hzlingdian.com/wx/2.png)

> 商户平台配置 支付时才使用
- 地址：https://pay.weixin.qq.com/partner/public/home?error_type=0
- 在平台里面获取到商户号partner/mch_id和商户密钥partnerkey
- 配置支付目录:配置到支付页面的上级文件夹
![image](http://media.hzlingdian.com/wx/1.png)

## 公众平台电商类H5开发-我的想法
> 分享只能分享出两个页面，商品详情页分享到商品详情页；其余页面全部分享到首页。这样只需要在商品详情页和首页处理微信授权即可，并且首次打开要么是首页，要么是商品详情页两张页面（其实是两张过渡页）。
> 在分享出去的首页和商品详情页第一张过渡页后面跟上分享人的用户id,如果没有分享人的用户id就认为自己是一级。在这两张页面经过跳转根据微信授权获取到微信用户信息并注册为本系统用户，关联分享人id

## 网页授权和JS-SDK授权
> 思路1：通过一张过渡页(即分享出去的页面和公众号菜单打开的页面)来跳转获取到code，回调地址写首页或者详情页的第二张过渡页，微信会回调到配置的首页或商品详情页的第二张过渡页，在首页和商品详情页的第二张过渡页获取微信用户信息并注册为本系统用户，有分享人id关联分享人id
> 思路2：在每个页面都需要设置JS-SDK授权，因为每个页面都有可能会调用分享，分享出去的页面要么是商品详情页要么是首页

相关代码下载
[code.rar](http://media.hzlingdian.com/wx/code.rar)

1. 前台相关代码：
- 首页或商品详情页第一张过渡页OAuthGetCode.html
```
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width,user-scalable=0">
<title></title>
<script type="text/javascript" src="jquery-3.0.0.min.js"></script>
</head>
<body>
	<script language="javascript" type="text/javascript">
        var urlfile = "http://wx.hzlingdian.com/";
		//获得url参数
		function getParpam(name) {
			var reg = new RegExp("(^|&)"+ name +"=([^&]*)(&|$)");
			var r = window.location.search.substr(1).match(reg);
			if(r!=null) return unescape(r[2]); return null;
		}
		
		var appid = getParpam('appid');
		//获取数据库中配置的微信id
		var state = getParpam('wechat');
	
		window.location.href = "https://open.weixin.qq.com/connect/oauth2/authorize?appid="+appid+"&redirect_uri="+urlfile+"/pageIndex.html&response_type=code&scope=snsapi_userinfo&state="+state+"&#wechat_redirect";
	</script>
</body>
</html>
```
- 首页或商品详情页第二张过渡页pageIndex.html
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="format-detection" content="telephone=no"/>
    <meta name="format-detection" content="email=no"/>
    <meta name="viewport"
          content="user-scalable=no, initial-scale=1, maximum-scale=1, minimum-scale=1, width=device-width;"/>
    <title></title>
    <script type="text/javascript" src="jquery-3.0.0.min.js"></script>
    <link rel="stylesheet" type="text/css" href="layer/need/layer.css"/>
    <script type="text/javascript" src="layer/layer.js"></script>
    <script type="text/javascript" src="common.js"></script>
</head>
<body>
</body>
<script type="text/javascript">
    $(function () {
        var code = GetParpam('code');
        var wechat = GetParpam('state');
        if (!wechat) {
            dataSave('errorContent', "缺少wechat");
            nextView('error.html');
        }
        dataSave('wechat', wechat);
        var data = {
            code: code,
            wechat: wechat
        }
        var urlfile = "http://wx.hzlingdian.com/";
        var url = urlfile + "/judge/page/by/code"; //这个接口内处理关联关系
        ajaxTool("post", data, url,
            function error(XMLHttpRequest, textStatus, errorThrown, fnErr) {
                alert(JSON.stringify(data))
            },
            function success(data) {
                if (!data.success) {
                    dataSave('errorContent', data.errMsg);
                    nextView('error.html');
                } else {
                    if (data.code == 1) {
                        var wechat = data.data.wechat;
                        var openid = data.data.openid;
                        if (!wechat) {
                            dataSave('errorContent', "缺少wechat");
                            nextView('error.html');
                        }
                        if (!openid) {
                            dataSave('errorContent', "缺少openid");
                            nextView('error.html');
                        }
                        dataSave('openid', openid);
                        nextView('index.html');
                    }
                }
            }, true
        );
    });
</script>
</html>
```
- 首页或商品详情页index.html
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="format-detection" content="telephone=no"/>
    <meta name="format-detection" content="email=no"/>
    <meta name="viewport"
          content="user-scalable=no, initial-scale=1, maximum-scale=1, minimum-scale=1, width=device-width;"/>
    <title>首页</title>
    <script type="text/javascript" src="jquery-3.0.0.min.js"></script>
    <link rel="stylesheet" type="text/css" href="layer/need/layer.css" />
    <script type="text/javascript" src="layer/layer.js"></script>
    <script src="common.js" type="text/javascript"></script>
    <script type="text/javascript" src="http://res.wx.qq.com/open/js/jweixin-1.0.0.js"></script>
</head>
<body>
</body>
<script>
    var urlfile = "http://wx.hzlingdian.com/";
    $(function() {
        initWX(dataGet('wechat'));
    });

    //JS-SDK授权
    function initWX(crwctUuid) {
        var urlString = getUrlAllPath();
        // 微信配置
        var data = "&urlString=" + encodeURIComponent(urlString) + "&crwctUuid=" + crwctUuid;
        var url = urlfile + "weixin/share/config";
        ajaxTool("post",data,url,
            function error(XMLHttpRequest, textStatus, errorThrown, fnErr){
                alert("error:" + data);
            },
            function success(data){
                if(!data.success) {
                    alert(data.errMsg);
                }else{
                    dataSave("appid", data.data.appid);
                    // 微信配置
                    wx.config({
                        debug: false,
                        appId: data.data.appid,
                        timestamp: data.data.timestamp,
                        nonceStr: data.data.nonceStr,
                        signature: data.data.signature,
                        jsApiList: [
                            'onMenuShareTimeline',
                            'onMenuShareAppMessage'
                        ]
                    });

                    wxReady();
                }
            },
            true
        );
    }

    function wxReady() {
        wx.ready(function(){
            var url = WEB_URL+'OAuthGetCode.html?appid='+encodeURIComponent(dataGet("appid"))
                +'&wechat='+encodeURIComponent(dataGet("wechat"));
            wx.onMenuShareTimeline({
                title: '分享测试！', // 分享标题
                link: url,// 分享链接，该链接域名或路径必须与当前页面对应的公众号JS安全域名一致
                imgUrl: '', // 分享图标
                success: function () {
                    // 用户确认分享后执行的回调函数
                },
                cancel: function () {
                    // 用户取消分享后执行的回调函数
                }
            });

            wx.onMenuShareAppMessage({
                title: '分享测试！', // 分享标题
                desc: '分享测试！！！', // 分享描述
                link: url, // 分享链接，该链接域名或路径必须与当前页面对应的公众号JS安全域名一致
                imgUrl: '', // 分享图标
                type: 'link', // 分享类型,music、video或link，不填默认为link
                dataUrl: '', // 如果type是music或video，则要提供数据链接，默认为空
                success: function () {
                    // 用户确认分享后执行的回调函数
                },
                cancel: function () {
                    // 用户取消分享后执行的回调函数
                }
            });
        });

        wx.error(function (res) {
            setTimeout(function () {
                // 自己试验出来的，签名失败后重签一次就可以，亲测很多项目有用
                // 网上没这种处理方法，主要是为了处理二次分享的问题，微信会在二次分享后给url后面增加值
                initWX(dataGet('wechat'));
            }, 300);
        });
    }

    function getUrlAllPath() {
        return location.href.split('#')[0];
    }
</script>
</html>
```
2. 后台主要代码
- /judge/page/by/code接口主要代码
```
/**
     * 根据code/wechat关联返回openid
     *
     * @param code code值
     * @param wechat 所属公众号
     * @return
     */
    @RequestMapping(value="/judge/page/by/code", method=RequestMethod.POST)
    public void judgePageByCode (String code, String wechat, HttpServletResponse response) {
        logger.info("[CoreRoundaboutRecordController]:begin judgePageByCode");
        
        CoreWechat coreWechat = new CoreWechat();
        coreWechat.setCrwctUuid(wechat);
        coreWechat = coreWechatService.getCoreWechat(coreWechat);

        OpenidAndAccessToken openidAndAccessToken = WeixinUtil.getOpenIdAndToken(coreWechat.getCrwctAppid(), coreWechat.getCrwctAppsecret(), null, code);
        if (null == openidAndAccessToken || null == openidAndAccessToken.getAccess_token() || null == openidAndAccessToken.getOpenid()) {
            writeAjaxJSONResponse(ResultMessageBuilder.build(false, -1, "网页授权失败,请重试!"), response);
            logger.info("[CoreRoundaboutRecordController]:end judgePageByCode");
            return;
        }

        //注册或更新用户
        WeixinUserInfo weixinUserInfo = WeixinUtil.getUserDetail(openidAndAccessToken.getAccess_token(), openidAndAccessToken.getOpenid());
        if (null == weixinUserInfo) {
            writeAjaxJSONResponse(ResultMessageBuilder.build(false, -1, "OAuth2.0拉取用户信息失败!"), response);
            logger.info("[CoreRoundaboutRecordController]:end judgePageByCode");
            return;
        }
        CoreUser coreUser = new CoreUser();
        String uuid = RandomUtil.generateString(16);
        coreUser.setCrusrUdate(new Date());
        coreUser.setCrusrWechat(wechat);
        coreUser.setCrusrOpenid(weixinUserInfo.getOpenid());
        coreUser.setCrusrWxNickname(weixinUserInfo.getNickname());
        coreUser.setCrusrWxSex(weixinUserInfo.getSex());
        coreUser.setCrusrWxCity(weixinUserInfo.getCity());
        coreUser.setCrusrWxCountry(weixinUserInfo.getCountry());
        coreUser.setCrusrWxProvince(weixinUserInfo.getProvince());
        coreUser.setCrusrWxHeadimgurl(weixinUserInfo.getHeadimgurl());

        CoreUser newCoreUser = this.coreUserService.getCoreUserByWechatAndOpenId(coreUser);
        if (null != newCoreUser) {
            uuid = newCoreUser.getCrusrUuid();
            coreUser.setCrusrUuid(uuid);
            coreUserService.updateCoreUser(coreUser);
        } else {
            coreUser.setCrusrUuid(uuid);
            coreUser.setCrusrName(weixinUserInfo.getNickname());
            coreUser.setCrusrCode(weixinUserInfo.getNickname());
            String md5PWD = MD5Util.encode("123456", Constant.DEFAULT_CHARSET);
            coreUser.setCrusrPassword(md5PWD);
            coreUser.setCrusrHead(null);
            coreUser.setCrusrType(1);
            coreUser.setCrusrStatus(1);
            coreUser.setCrusrCdate(new Date());
            if (null != weixinUserInfo.getSex() && ("1").equals(weixinUserInfo.getSex())) {
                coreUser.setCrusrGender(1);
            }
            if (null != weixinUserInfo.getSex() && ("2").equals(weixinUserInfo.getSex())) {
                coreUser.setCrusrGender(2);
            }
            coreUserService.insertCoreUser(coreUser);
        }

        Map<String, Object> map = new HashMap<String, Object>();
        map.put("wechat", wechat);
        map.put("openid", weixinUserInfo.getOpenid());
        writeAjaxJSONResponse(ResultMessageBuilder.build(true, 1, "跳转到业务首页,返回所属公众号和openid!", map), response);
    }
```
- 网页授权weixin/share/config主要代码
coreWechatController
```
    /**
	 * 获取JS-SDK配置
	 * 
	 * @param crwctUuid 公众号标识
	 * @param urlString URL路径
	 * @return
	 */
	@RequestMapping(value = "/share/config", method = RequestMethod.POST)
	public void getShareConfig(String crwctUuid, String urlString, HttpServletRequest request, HttpServletResponse response) {
	    ShareConfig shareConfig = this.coreWechatService.getShareConfig(crwctUuid, urlString);
        writeAjaxJSONResponse(ResultMessageBuilder.build(true, 1, "获取JS-SDK配置成功！", shareConfig), response);
	}
```
coreWechatServiceImpl
```
    //获取AccessToken，设置7000秒就到期，微信那边7200秒到期
	public String getAccessToken(String crwctUuid) {
		String accessToken = "";
		CoreWechat coreWechat = new CoreWechat();
		coreWechat.setCrwctUuid(crwctUuid);
		coreWechat = this.getCoreWechat(coreWechat);
		if (null != coreWechat) {
			String appid = coreWechat.getCrwctAppid();
			Date now = new Date();
			if (now.getTime() >= coreWechat.getCrwctAccessTime().getTime()) {
				AccessTokenModel accessTokenModel = WeixinUtil.getAccessToken(coreWechat.getCrwctAppid(), coreWechat.getCrwctAppsecret());
				if (null != accessTokenModel) {
					accessToken = accessTokenModel.getAccess_token();
					coreWechat = new CoreWechat();
					coreWechat.setCrwctAppid(appid);
					coreWechat.setCrwctAccessTime(DateUtil.addSecond(now, 7000));
					coreWechat.setCrwctAccessToken(accessToken);
					this.updateCoreWechatByAppid(coreWechat);
				}
			} else {
				accessToken = coreWechat.getCrwctAccessToken();
			}
		}
		
		return accessToken;
	}

    //获取授权凭证，判断有效期
	public ShareConfig getShareConfig(String crwctUuid, String urlString) {
		ShareConfig shareConfig = new ShareConfig();
		CoreWechat coreWechat = new CoreWechat();
		coreWechat.setCrwctUuid(crwctUuid);
		coreWechat = this.getCoreWechat(coreWechat);
		if (null != coreWechat) {
			String appid = coreWechat.getCrwctAppid();
			String jsapiTicket = coreWechat.getCrwctJsapiTicket();
			Date now = new Date();
			if (now.getTime() >= coreWechat.getCrwctJsapiTime().getTime()) {
				jsapiTicket = WeixinUtil.getJsApiTicket(this.getAccessToken(crwctUuid));
				coreWechat = new CoreWechat();
				coreWechat.setCrwctAppid(appid);
				coreWechat.setCrwctJsapiTime(DateUtil.addSecond(now, 7000));
				coreWechat.setCrwctJsapiTicket(jsapiTicket);
				this.updateCoreWechatByAppid(coreWechat);
			}
			shareConfig = WeixinUtil.makeWXTicket(jsapiTicket, appid, urlString);
		}
		
		return shareConfig;
	}

}
```
WeixinUtil微信工具类
```
    // 主动发送客服消息url
	public final static String SEND_CUSTOM_URL = "https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=ACCESS_TOKEN";
	// 微信模板消息调用接口URL
	public final static String TEMPLATE_MSG_URL = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=ACCESS_TOKEN";
	// 通过OpenID获取查询用户所在分组url
	public final static String GET_PERSONGROUPID_URL = "https://api.weixin.qq.com/cgi-bin/groups/getid?access_token=ACCESS_TOKEN";
	// 生成临时二维码url
	public final static String TEMPORARY_QRCODE_URL = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=ACCESS_TOKEN";
	// 生成永久二维码url
	public final static String PERMANENT_QRCODE_URL = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=ACCESS_TOKEN";
	// 换取二维码url
	protected final static String GET_QRCODE_URL = "https://mp.weixin.qq.com/cgi-bin/shoMyna Wangrcode?ticket=TICKET";
	// 获取关注者列表url
	public final static String GET_USERLIST_URL = "https://api.weixin.qq.com/cgi-bin/user/get?access_token=ACCESS_TOKEN&next_openid=NEXT_OPENID";
	// 获取所有分组信息url
	public final static String GET_GROUPS_URL = "https://api.weixin.qq.com/cgi-bin/groups/get?access_token=ACCESS_TOKEN";
	// 创建分组url
	public final static String CREATE_GROUPS_URL = "https://api.weixin.qq.com/cgi-bin/groups/create?access_token=ACCESS_TOKEN";
	// 修改分组url
	public final static String UPDATE_GROUPS_URL = "https://api.weixin.qq.com/cgi-bin/groups/update?access_token=ACCESS_TOKEN";
	// 移动用户分组url
	public final static String REMOVE_MEMBER_URL = "https://api.weixin.qq.com/cgi-bin/groups/members/update?access_token=ACCESS_TOKEN";
	// 上传多媒体文件url
	public final static String UPLOAD_MEDIA_URL = "http://file.api.weixin.qq.com/cgi-bin/media/upload?access_token=ACCESS_TOKEN&type=TYPE";
	// 下载多媒体文件url
	public final static String DOWNLOAD_MEDIA_URL = "http://file.api.weixin.qq.com/cgi-bin/media/get?access_token=ACCESS_TOKEN&media_id=MEDIA_ID";
	// 菜单查询（GET）
	public final static String GET_MENU_URL = "https://api.weixin.qq.com/cgi-bin/menu/get?access_token=ACCESS_TOKEN";
	// 菜单删除（GET）
	public final static String DELETE_MENU_URL = "https://api.weixin.qq.com/cgi-bin/menu/delete?access_token=ACCESS_TOKEN";
	// OAuth2.0通过code换取网页授权access_token和openid(grant_type为authorization_code或refresh_token)
	public final static String OAUTH2_ACCESSTOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=APPID&secret=SECRET&code=CODE&grant_type=authorization_code";
	// OAuth2.0拉取用户信息(需scope为 snsapi_userinfo)
	public final static String OAUTH2_USERINFO_URL = "https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN";
	// 根据OpenID机制获得用户详细信息
	public final static String OPENID_INFO="https://api.weixin.qq.com/cgi-bin/user/info?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN";
	// 获取jsapi_ticket的接口地址（GET） 缓存7200秒  
	public final static String JSAPI_TICKET_URL = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=ACCESS_TOKEN&type=jsapi";
	// 获取access_token的接口地址（GET） 限200（次/天）  
	public final static String ACCESS_TOKEN_URL = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=SECRET";
	
	/**
	 * 获取微信JS-SDK接口的临时票据jsapi_ticket,次数有限，需要保存
	 * 
	 * @param access_token 全局access_token
	 * @return
	 */
	public static String getJsApiTicket(String access_token) {
		String requestUrl = JSAPI_TICKET_URL.replace("ACCESS_TOKEN", access_token);
		// 发起GET请求获取凭证
		JSONObject jsonObject = HttpUrlConnectionUtil.sendWxHttpsRequest(requestUrl, "GET", null);
		String ticket = null;
		if (null != jsonObject) {
			try {
				ticket = jsonObject.getString("ticket");
			} catch (JSONException e) {	
				logger.error(e.getMessage());
				return "";
			}
		}
		return ticket;
	}
	
	/**
	 * 获取全局access_token,次数有限，需要保存
	 * 
	 * @param appid
	 * @param secret
	 * @return
	 */
	public static AccessTokenModel getAccessToken(String appid, String secret) {
		String requestUrl = ACCESS_TOKEN_URL.replace("APPID", appid).replace("SECRET", secret);
		JSONObject jsonObject = HttpUrlConnectionUtil.sendWxHttpsRequest(requestUrl, "GET", null);
		if (null != jsonObject) {
			return JSON.parseObject(jsonObject.toString(), AccessTokenModel.class);
		}
		
		return null;
	}
	
	/**
	 * 通过code获取网页授权access_token,次数不限,不需要保存
	 * 
	 * @param appid
	 * @param appsecret
	 * @param grantType,可不传，默认authorization_code
	 * @param code
	 * @return
	 */
	public static OpenidAndAccessToken getOpenIdAndToken(String appid,String appsecret, String grantType, String code){
		if(StringUtil.isEmpty(grantType)) {
			grantType = "authorization_code";
		}
		String requestUrl = OAUTH2_ACCESSTOKEN_URL.replace("APPID", appid).replace("SECRET", appsecret).replace("CODE", code).replace("authorization_code", grantType);
		JSONObject jsonObject = HttpUrlConnectionUtil.sendWxHttpsRequest(requestUrl, "GET", null);
		if (null != jsonObject) {
			return JSON.parseObject(jsonObject.toString(), OpenidAndAccessToken.class);
		}
		
		return null;
	}
	
	/**
	 * 发送客服消息方法
	 * 
	 * @param accessToken 全局access_token
	 * @param jsonMsg json格式客服消息
	 * @return true|false
	 */
	public static boolean sendCustomMessage(String accessToken, String jsonMsg) {
		boolean result = false;
		String requestUrl = SEND_CUSTOM_URL.replace("ACCESS_TOKEN", accessToken);
		// 发送客服消息
		JSONObject jsonObject = HttpUrlConnectionUtil.sendWxHttpsRequest(requestUrl, "POST", jsonMsg);
		if (null != jsonObject) {
			int errorCode = jsonObject.getIntValue("errcode");
			String errorMsg = jsonObject.getString("errmsg");
			if (0 == errorCode) {
				result = true;
				logger.info(errorMsg);
			} else {
				logger.error(errorMsg);
			}
		}
		return result;
	}
	
	/**
	 * 下载多媒体文件
	 * 
	 * @param accessToken 全局access_token
	 * @param mediaId 媒体文件ID
	 * @param savePath 保存路径目录
	 * @return String 保存文件名
	 */
	public static String getMedia(String accessToken, String mediaId, String savePath) {
		String filePath = null;
		String requestUrl = DOWNLOAD_MEDIA_URL.replace("ACCESS_TOKEN", accessToken).replace("MEDIA_ID", mediaId);
		try{
			URL url = new URL(requestUrl);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setDoInput(true);
			conn.setRequestMethod("GET");
			if (!savePath.endsWith("\\")) {
				savePath += "\\";
			}
			// 根据内容类型获取扩展名
			String fileExt = StringUtil.getFileExt(conn.getHeaderField("Content-Type"));
			// 将mediaId作为文件名
			filePath = savePath + mediaId + fileExt;
			BufferedInputStream bis = new BufferedInputStream(
					conn.getInputStream());
			FileOutputStream fos = new FileOutputStream(new File(filePath));
			byte[] buf = new byte[1024];
			int size = 0;
			while ((size = bis.read(buf)) != -1) {
				fos.write(buf, 0, size);
			}
			fos.close();
			bis.close();
			conn.disconnect();
			logger.info("下载媒体文件成功,filePath=" + filePath);
			return mediaId + fileExt;
		}
		catch (Exception e) {
			logger.error("下载媒体文件失败:{}", e);
		}
		return "";
	}
	
	/**
	 * 查询用户所在分组
	 * 
	 * @param accessToken 全局access_token
	 * @param openId  普通用户的标识，对当前公众号唯一
	 * @return groupid
	 */
	public static int getPersonGroupId(String accessToken, String openId) {
		int groupId = 0;
		String requestUrl = GET_PERSONGROUPID_URL.replace("ACCESS_TOKEN", accessToken);
		// 需要提交的json数据
		String jsonData = "{\"openid\":\"%s\"}";
		// 创建分组
		JSONObject jsonObject = HttpUrlConnectionUtil.sendWxHttpsRequest(requestUrl, "POST",
				String.format(jsonData, openId));
		if (null != jsonObject) {
			try {
				groupId = jsonObject.getIntValue("groupid");
			}
			catch (JSONException e) {
				groupId = -1;
				int errorCode = jsonObject.getIntValue("errcode");
				String errorMsg = jsonObject.getString("errmsg");
				logger.error(errorCode + ":" +errorMsg);
			}
		}
		return groupId;
	}
	
	/**
	 * 发送模版消息
	 * 
	 * @param jsonStr
	 * @param accessToken 全局access_token
	 * @return
	 */
	public static String sendTemplateMsg(String jsonStr, String accessToken) {
		String requestUrl = WeixinUtil.TEMPLATE_MSG_URL.replace("ACCESS_TOKEN", accessToken);
		JSONObject jsonObject = HttpUrlConnectionUtil.sendWxHttpsRequest(requestUrl, "POST", jsonStr);
		return jsonObject.toString();
	}
	
	/**
	 * OAuth2.0拉取用户信息(需scope为 snsapi_userinfo)
	 * 
	 * @param access_token 网页授权access_token
	 * @param openid
	 * @return
	 */
	public static WeixinUserInfo getUserDetail(String access_token, String openid){
		String requestUrl = OAUTH2_USERINFO_URL.replace("ACCESS_TOKEN", access_token).replace("OPENID", openid);
		JSONObject jsonObject = HttpUrlConnectionUtil.sendWxHttpsRequest(requestUrl, "GET", null);
		if (null != jsonObject) {
			return JSON.parseObject(jsonObject.toString(), WeixinUserInfo.class);
		}
		
		return null;
	}

	/**
	 * 根据OpenID机制获得用户详细信息
	 * 
	 * @param access_token 网页授权access_token
	 * @param openid
	 * @return
	 */
	public static WeixinUserInfo getUserDetailByOpenID(String access_token, String openid){
		String requestUrl = OPENID_INFO.replace("ACCESS_TOKEN", access_token).replace("OPENID", openid);
		JSONObject jsonObject = HttpUrlConnectionUtil.sendWxHttpsRequest(requestUrl, "GET", null);
		if (null != jsonObject) {
			return JSON.parseObject(jsonObject.toString(), WeixinUserInfo.class);
		}
		
		return null;
	}

	/**
	 * 微信开发者验证
	 * 
	 * @param wxToken  
	 * @param tokenModel
	 * @return
	 */
	public static String validate(String wxToken, CheckModel tokenModel){
		String signature = tokenModel.getSignature();
		Long timestamp = tokenModel.getTimestamp();
		Long nonce = tokenModel.getNonce();
		String echostr = tokenModel.getEchostr();
		if(signature != null && timestamp != null && nonce != null) {
			String[] str = {wxToken, timestamp+"", nonce+""};
			Arrays.sort(str); // 字典序排序
			String bigStr = str[0] + str[1] + str[2];
	        // SHA1加密	
	        String digest = Sha1Util.getSha1(bigStr).toLowerCase();
	        // 确认请求来至微信
	        if (digest.equals(signature)) {
	        	return echostr;
	        }
		}
		return "error";
	}

	public static ShareConfig makeWXTicket(String jsapi_ticket, String appid, String url) {
	    String nonce_str = StringUtil.create_nonce_str();
	    String timestamp = StringUtil.create_timestamp();
	    String string1;
	    String signature = "";

	    //注意这里参数名必须全部小写，且必须有序
	    string1 = "jsapi_ticket=" + jsapi_ticket +
	              "&noncestr=" + nonce_str +
	              "&timestamp=" + timestamp +
	              "&url=" + url;
	    
	    signature = Sha1Util.getSha1(string1);
	    ShareConfig shareConfig = new ShareConfig();
	    shareConfig.setUrl(url);
	    shareConfig.setAppid(appid);
	    shareConfig.setJsapi_ticket(jsapi_ticket);
	    shareConfig.setNonceStr(nonce_str);
	    shareConfig.setSignature(signature);
	    shareConfig.setTimestamp(timestamp);

	    return shareConfig;
	}
```
