package com.isoftstone.insurance.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.params.AuthPNames;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.NTLMSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;










import net.sf.json.JSONObject;

public class HttpClientUtils {
	private static Logger logger = Logger.getLogger("HttpClientUtils");

	/** 连接超时时间（默认3秒 3000ms） 单位毫秒（ms） */
	private int connectionTimeout = 30000;

	/** 读取数据超时时间（默认30秒 30000ms） 单位毫秒（ms） */
	private int soTimeout = 30000;

	/** 代理主机名 */
	private String proxyHost;

	/** 代理端口 */
	private int proxyPort;

	/** 代理主机用户名 */
	private String proxyUser;

	/** 代理主机密码 */
	private String proxyPwd;

	/** 代理主机域 */
	private String proxyDomain;

	/** 字符集设置，默认UTF-8 */
	private String charset = "UTF-8";

	private Header[] httpsCookieHeaders;

	public String getProxyUser() {
		return proxyUser;
	}

	public void setProxyUser(String proxyUser) {
		this.proxyUser = proxyUser;
	}

	public String getProxyPwd() {
		return proxyPwd;
	}

	public void setProxyPwd(String proxyPwd) {
		this.proxyPwd = proxyPwd;
	}

	public String getProxyDomain() {
		return proxyDomain;
	}

	public void setProxyDomain(String proxyDomain) {
		this.proxyDomain = proxyDomain;
	}

	public int getConnectionTimeout() {
		return connectionTimeout;
	}

	public void setConnectionTimeout(int connectionTimeout) {
		this.connectionTimeout = connectionTimeout;
	}

	public String getProxyHost() {
		return proxyHost;
	}

	public void setProxyHost(String proxyHost) {
		this.proxyHost = proxyHost;
	}

	public int getProxyPort() {
		return proxyPort;
	}

	public void setProxyPort(int proxyPort) {
		this.proxyPort = proxyPort;
	}

	public int getSoTimeout() {
		return soTimeout;
	}

	public void setSoTimeout(int soTimeout) {
		this.soTimeout = soTimeout;
	}

	public String getCharset() {
		return charset;
	}

	public void setCharset(String charset) {
		this.charset = charset;
	}

	private static X509TrustManager tm = new X509TrustManager() {
		public void checkClientTrusted(X509Certificate[] xcs, String string)
				throws CertificateException {
		}

		public void checkServerTrusted(X509Certificate[] xcs, String string)
				throws CertificateException {
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	};

	/**
	 * 获取一个针对http的HttpClient
	 */
	private HttpClient getHttpClient()// boolean useHttps
			throws KeyManagementException, NoSuchAlgorithmException {
		HttpParams httpParams = new BasicHttpParams();
		// 设置代理
		// if (!StringUtils.isEmpty(proxyHost)) {
		// HttpHost proxy = new HttpHost(proxyHost, proxyPort);
		// httpParams.setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
		// }

		// 设置超时时间
		httpParams.setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT,
				connectionTimeout);
		httpParams.setParameter(CoreConnectionPNames.SO_TIMEOUT, soTimeout);
		DefaultHttpClient httpclient = new DefaultHttpClient();
		httpclient.setParams(httpParams);
		// 代理需要认证
		if (proxyUser != null) {
			if (proxyDomain != null) {// NTLM认证模式
				httpclient.getAuthSchemes().register("ntlm",
						new NTLMSchemeFactory());
				httpclient.getCredentialsProvider().setCredentials(
						AuthScope.ANY,
						new NTCredentials(proxyUser, proxyPwd, proxyHost,
								proxyDomain));
				List<String> authpref = new ArrayList<String>();
				authpref.add(AuthPolicy.NTLM);
				httpclient.getParams().setParameter(
						AuthPNames.TARGET_AUTH_PREF, authpref);
			} else {// BASIC模式
				CredentialsProvider credsProvider = new BasicCredentialsProvider();
				credsProvider.setCredentials(
						new AuthScope(proxyHost, proxyPort),
						new UsernamePasswordCredentials(proxyUser, proxyPwd));
				httpclient.setCredentialsProvider(credsProvider);
			}
		}
		httpclient.addRequestInterceptor(new HttpRequestInterceptor() {
			public void process(final HttpRequest request,
					final HttpContext context) throws HttpException,
					IOException {
				if (!request.containsHeader("Accept")) {
					request.addHeader("Accept", "*/*");
				}
				if (request.containsHeader("User-Agent")) {
					request.removeHeaders("User-Agent");
				}
				if (request.containsHeader("Connection")) {
					request.removeHeaders("Connection");
				}
				request
						.addHeader("User-Agent",
								"Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0");
				request.addHeader("Connection", "keep-alive");
			}
		});
		return httpclient;
	}

	/**
	 * 获取一个针对https的HttpClient
	 */
	private HttpClient getHttpsClient() throws KeyManagementException,
			NoSuchAlgorithmException {
		HttpClient httpclient = getHttpClient();
		SSLContext sslcontext = SSLContext.getInstance("TLS");
		sslcontext.init(null, new TrustManager[] { tm }, null);
		SSLSocketFactory ssf = new SSLSocketFactory(sslcontext,
				SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		httpclient.getConnectionManager().getSchemeRegistry().register(
				new Scheme("https", 443, ssf));
		return httpclient;
	}

	/**
	 * 创建post请求
	 * 
	 * @param url
	 * @return HttpPost
	 */
	private HttpPost getHttpPost(String url) {
		// 创建post请求
		HttpPost post = new HttpPost(url);
		if (httpsCookieHeaders != null && httpsCookieHeaders.length > 0) {
			post.setHeaders(httpsCookieHeaders);
		}
		return post;
	}

	/**
	 * 创建get请求
	 * 
	 * @param url
	 * @return HttpGet
	 */
	private HttpGet getHttpGet(String url) {
		HttpGet get = new HttpGet(url);
		if (httpsCookieHeaders != null && httpsCookieHeaders.length > 0) {
			get.setHeaders(httpsCookieHeaders);
		}
		return get;
	}

	/**
	 * 获取response里的cookies
	 * 
	 * @param response
	 */
	private void getRequestCookieHeader(HttpResponse response) {
		Header[] responseHeaders = response.getHeaders("Set-Cookie");
		if (responseHeaders == null || responseHeaders.length <= 0) {
			return;
		}
		httpsCookieHeaders = new BasicHeader[responseHeaders.length];
		for (int i = 0; i < responseHeaders.length; i++) {
			httpsCookieHeaders[i] = new BasicHeader("Cookie",
					responseHeaders[i].getValue());
		}

	}


	/**
	 * 以get方式请求，返回String型结果
	 * 
	 * @param url
	 * @return
	 * @throws Exception
	 */
	public String doGet(String url) throws Exception {
		HttpClient httpclient = getHttpsClient();
		HttpGet get = getHttpGet(url);
		String responseBody = null;
		try {
			HttpResponse response = httpclient.execute(get);
			getRequestCookieHeader(response);

		} catch (java.net.SocketTimeoutException ste) {
			responseBody = ste.getMessage();
		} catch (Exception e) {
			responseBody = e.getMessage();
			e.printStackTrace();
		} finally {
			httpclient.getConnectionManager().shutdown();
		}
		return responseBody;
	}

	String sessionID = "";

	/**
	 * 避免HttpClient的”SSLPeerUnverifiedException: peer not authenticated”异常
	 * 不用导入SSL证书
	 * 
	 * @author shipengzhi(shipengzhi@sogou-inc.com)
	 * 
	 */
	public static class WebClientDevWrapper {

		public static org.apache.http.client.HttpClient wrapClient(
				org.apache.http.client.HttpClient base) {
			try {
				SSLContext ctx = SSLContext.getInstance("TLS");
				X509TrustManager tm = new X509TrustManager() {
					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}

					public void checkClientTrusted(X509Certificate[] arg0,
							String arg1) throws CertificateException {
					}

					public void checkServerTrusted(X509Certificate[] arg0,
							String arg1) throws CertificateException {
					}
				};
				ctx.init(null, new TrustManager[] { tm }, null);
				SSLSocketFactory ssf = new SSLSocketFactory(ctx,
						SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
				SchemeRegistry registry = new SchemeRegistry();
				registry.register(new Scheme("https", 443, ssf));
				ThreadSafeClientConnManager mgr = new ThreadSafeClientConnManager(
						registry);
				return new DefaultHttpClient(mgr, base.getParams());
			} catch (Exception ex) {
				ex.printStackTrace();
				return null;
			}
		}
	}

	/**
	 * 以post方式请求，返回String型结果
	 * 
	 * @param url
	 * @param nvps
	 * @return
	 * @throws Exception
	 */
	public String doPost(String url, String sendJSOn, boolean bl)
			throws Exception {
		HttpClient httpclient = getHttpsClient();
		HttpPost post = getHttpPost(url);
		String responseBody = null;
		try {
			logger.info("访问地址:" + url);
			logger.info("发送数据:" + sendJSOn);
			// 解决中文乱码问题
			StringEntity entity = new StringEntity(sendJSOn.toString(), "utf-8");
			entity.setContentEncoding("UTF-8");
			entity.setContentType("application/json;charset=UTF-8");

			post.setEntity(entity);
			 post.addHeader("Content-Type", "application/json; charset=utf-8");
			if (!sessionID.equals(""))
				post.setHeader("Cookie", sessionID);
			HttpResponse response = httpclient.execute(post);
			getRequestCookieHeader(response);

			if (bl) {
				StringBuffer sbf = new StringBuffer();
				Header[] map = response.getHeaders("Set-Cookie");
				for (Header o : map) {
					sbf.append(o.getValue()).append(";");
				}
				sessionID = sbf.toString();
				// logger.info("SESSIONID:" + sessionID);
			}
			responseBody = EntityUtils.toString(response.getEntity(), "utf-8");
			responseBody=new String(responseBody.getBytes(),"utf-8");
			logger.info(response.getStatusLine().getStatusCode() + "结果："
					+ responseBody);
			response.getEntity().getContent();
			// responseBody = IOUtils.toString(,
			// charset);

		} catch (java.net.SocketTimeoutException ste) {
			responseBody = ste.getMessage();
		} catch (Exception e) {
			responseBody = e.getMessage();
			e.printStackTrace();
		} finally {
			httpclient.getConnectionManager().shutdown();
		}
		return responseBody;
	}

	static String url = "";
	static String data = "";

	
	
	private static String obtainLocalMD5(String requestStr) throws UnsupportedEncodingException
	{
		
		// 本地密钥(加密因子) 从t_dept表中的secretkey获取
		String cipherCode = "A98Gdgksg8763uasiPP0";
		
		// 移除key,然后转换成json。 也就是获取原来的json
		JSONObject json = JSONObject.fromObject(requestStr);
////		json.remove("key");
		String  str= json.toString();
		// 将数据转换UTF-8，保持数据统一(数据带中文时需要特殊处理)
		 String originStr = URLEncoder.encode(requestStr,"UTF-8");
		
		 logger.info(originStr + cipherCode);
		// 转换成md5
		 System.out.println("123456加密后：" + MD5Utils.md5Encode("123456"));
		return MD5Utils.md5Encode(originStr + cipherCode);
	}


	
	private static void property() {
		HttpClientUtils httpClient2 = new HttpClientUtils();
		httpClient2.setConnectionTimeout(60000);
		httpClient2.setSoTimeout(60000);
		
		//url="http://115.29.175.29:8080/regulation/interface/insurer/property";
		
		url="http://127.0.0.1:8080/regulation/interface/insurer/property";
		
		String sendJson= "\"data\":{\"deptcode\":\"Cxyza\",\"year\":\"2017\",\"month\":\"7\"},\"listagent\":[{\"deptname\":\"太平财产保险有限公司深圳分公司\",\"type\":\"6\",\"insurancename\":\"家庭财产保险\",\"premiumnow\":\"100.0000\",\"premiumpre\":\"200.00\",\"commissionnow\":\"100.00\",\"commissionpre\":\"200.00\"}],\"listclaim\":[{\"deptname\":\"太平财产保险有限公司深圳分公司\",\"caseclosenow\":\"100\",\"turnovernow\":\"100.00\"}],\"listsum\":[{\"typesub\":\"6\",\"amount\":\"10000.0000\",\"premiumproperty\":\"100.00\",\"premiumauto\":\"10.0000\",\"premiumlife\":\"100.00\",\"premiumlifenew\":\"10.0000\",\"premiumsum\":\"200.0000\",\"premiumnet\":\"10.0000\",\"premiumtel\":\"10.0000\"}]";
		
		try {
			String key = obtainLocalMD5("{"+sendJson+"}");
			data = "{\"key\":\""+key+"\","+sendJson+"}";
			
			httpClient2.doPost(url, data, false);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	
	public static void main(String args[]) throws Exception {
		//agent();
		claim();
		//property();
	}

}
