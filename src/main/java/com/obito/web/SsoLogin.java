package com.obito.web;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.obito.metadata.SPMetadata;

public class SsoLogin extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static Logger log=LoggerFactory.getLogger(SsoLogin.class);

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		log.info("AuthnRequest recieved");
		//next version should validte the AuthnRequest 
		Map<String,Object> map = new HashMap<String,Object>();  
        Enumeration paramNames = request.getParameterNames();  
        while (paramNames.hasMoreElements()) {  
            String paramName = (String) paramNames.nextElement();  

            String[] paramValues = request.getParameterValues(paramName);  
            if (paramValues.length >0) {  
                String paramValue = paramValues[0];  
                if (paramValue.length() != 0) {  
                    map.put(paramName, paramValue);  
                }  
            }  
        }  

        Set<Map.Entry<String, Object>> set = map.entrySet();  
        log.info("==============================================================");  
        for (Map.Entry entry : set) {  
            log.info(entry.getKey() + ":" + entry.getValue());  
        }  
        log.info("=============================================================");  
		
		
	    request.getRequestDispatcher("login.jsp").forward(request, response);
		
		
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		String username=request.getParameter("username");
		String pwd=request.getParameter("pwd");
		if(username.equals("obito") && pwd.equals("123456")) {
			response.sendRedirect(SPMetadata.ASSERTION_CONSUMER_URL+"?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D");
			return;
		}else {
			response.sendRedirect("login.jsp");
		}
	}

	@Override
	public void init() throws ServletException {
		super.init();
	    try {
		 JavaCryptoValidationInitializer javaCryptoValidationInitializer =
	                new JavaCryptoValidationInitializer();
           //这个方法应该在OpenSAML初始化之前被调用，
           //来确保当前的JCE环境可以符合要求：AES/CBC/ISO10126Padding
           // 对于XML的加密，JCE需要支持ACE（128/256），并使用ISO10126Padding（填充位）
           javaCryptoValidationInitializer.init();
       } catch (InitializationException e) {
           e.printStackTrace();
       }

       //打印当前已经被安装的所有JCE的provider
       for (Provider jceProvider : Security.getProviders()) {
           log.info(jceProvider.getInfo());
       }

       try {
           log.info(" accessFilter Initializing");
           InitializationService.initialize();
       } catch (InitializationException e) {
           throw new RuntimeException("Initialization failed");
       }   
	}
}
