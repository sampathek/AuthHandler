package com.noetic.auth;

import org.apache.log4j.BasicConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test class!
 *
 */
public class App {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(App.class);
	
	public static void main(String[] args) {
		
		BasicConfigurator.configure();
		BasicAuthHandler authHandler = new BasicAuthHandler();

		System.setProperty("clientProfile", "NOETICDEMO");
		System.setProperty("deployProfile", "STAGING");

		LOGGER.info("isAuthenticated: "
				+ authHandler.processSecurity("YXBpQG5vZXRpYzpuZGVtb2YxNC0zYjkzLTRjMmItOTNkYy0yODU4MTFlOHN0Zw=="));
	}
}
