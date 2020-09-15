package com.noetic.auth;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;	

public class BasicAuthHandler implements Handler {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(BasicAuthHandler.class);
	
	protected final Map<String, Object> properties = new HashMap<String, Object>();
	
    public void addProperty(String name, Object value) {
        properties.put(name, value);
    }

    public Map getProperties() {
        return properties;
    }

    public boolean handleRequest(MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MessageContext
                = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(
                org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        
        if (headers != null && headers instanceof Map) {
            Map headersMap = (Map) headers;
            if (headersMap.get("Authorization") == null) {
                headersMap.clear();
                axis2MessageContext.setProperty("HTTP_SC", "401");
                headersMap.put("WWW-Authenticate", "Basic realm=\"WSO2 ESB\"");
                axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
                messageContext.setProperty("RESPONSE", "true");
                messageContext.setTo(null);
                Axis2Sender.sendBack(messageContext);
                return false;

            } else {
                String authHeader = (String) headersMap.get("Authorization");
                String credentials = authHeader.substring(6).trim();
                if (processSecurity(credentials)) {
                    return true;
                } else {
                    headersMap.clear();
                    axis2MessageContext.setProperty("HTTP_SC", "403");
                    axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
                    messageContext.setProperty("RESPONSE", "true");
                    messageContext.setTo(null);
                    Axis2Sender.sendBack(messageContext);
                    return false;
                }
            }
        }
        return true;
    }

    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }
	
    public boolean processSecurity(String credentials) {
		
    	String client = System.getProperty("clientProfile");
    	String profile = System.getProperty("deployProfile");
    	
    	try {
			String decodedCredentials = new String(Base64.getDecoder().decode(credentials.getBytes()));
			String userName = decodedCredentials.split(":")[0];
			String password = decodedCredentials.split(":")[1];

			LOGGER.info("Client Profile= {} || Deploy Profile= {}" , client, profile);
			
			Properties properties = new Properties();
			try {
			    properties.load(
			    		BasicAuthHandler.class.getClassLoader().getResourceAsStream("auth.properties"));
			} catch (Exception e1) {
			    LOGGER.error("Error initialising property file.", e1);
			}

			String propUserName = properties.getProperty(client.toLowerCase() + "." + profile.toLowerCase() + ".username");
			String propPassword = properties.getProperty(client.toLowerCase() + "." + profile.toLowerCase() + ".password");

			if (propUserName.equals(userName) && propPassword.equals(password)) {
				return true;
			} 
		} catch (Exception e) {
			LOGGER.error("Error in Noetic Auth. Please configure properties for {}-{}", client, profile, e);
		}
    	
    	return false;
    }
}
	
