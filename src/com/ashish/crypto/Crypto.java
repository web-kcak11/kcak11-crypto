package com.ashish.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;


/**
 * Servlet implementation class Crypto
 */
@WebServlet("/Crypto")
public class Crypto extends HttpServlet {
	private static final long serialVersionUID = 1L;

    /**
     * Default constructor. 
     */
    public Crypto() {}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.getWriter().append("Please Use the POST Method for Testing Encryption/Decryption.");
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		StringBuffer jb = new StringBuffer();
		  String line = null;
		  try {
		    BufferedReader reader = request.getReader();
		    while ((line = reader.readLine()) != null)
		      jb.append(line);
		  } catch (Exception e) {
			  /*report an error*/ 			  
		  }

		JSONObject jsonObject =  new JSONObject(jb.toString());
		
		String encryptedKey=jsonObject.getString("encryptedKey");
		String encryptedMessage=jsonObject.getString("encryptedMessage");
		  
		response.setContentType("application/json");
		try {
			String decryptedKey=RSAUtil.decrypt(encryptedKey);
			String decryptedMessage=AESUtil.decryptWithPkcs7(encryptedMessage, decryptedKey);
			response.getWriter().append("{\"decryptedMessage\":\"" + decryptedMessage + "\"}");
		} catch(Exception e) {
			response.setStatus(500);
			response.getWriter().append("{\"error\":\"Unable to decrypt the given input.\"}");
			System.out.println(e);
			e.printStackTrace();
		}
	}

}
