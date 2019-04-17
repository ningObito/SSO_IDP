package com.obito.web;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

}
