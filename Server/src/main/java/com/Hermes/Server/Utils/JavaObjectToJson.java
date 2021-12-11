package com.Hermes.Server.Utils;

import org.springframework.stereotype.Service;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

@Service
public class JavaObjectToJson {

	public String convert(Object javaObject) {
		
		String json = "";
		Gson gson = new GsonBuilder().create();
		json = gson.toJson(javaObject);
		return json;
				
	}
	
}

