package org.saiku.service.util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.rmi.RemoteException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.imodule.ws.soa.um.UmSoaPortTypeProxy;
import com.imodule.ws.soa.um.result.xsd.UmLoginResult;

/**
 * Get password from properties file,for validate password.
 * ps：  properties file path keep on with this Class path .
 * @author S0111
 *
 */
public class GetFixedPasswordUtil {
	
	private String SAIKU_USER_PASSWORD = "saikuUserPassword";
	private String FILE_NAME = "saikuUser.properties";
//	FileInputStream in = null;
	InputStream ins = null;
	String  saikuUserPassword = null;
	protected final Log logger = LogFactory.getLog(getClass());
	
	/**
	 * Get local password from properties file.
	 * @return
	 */
	public String getSaikuUserPassword(){
		try{
			Properties properties = new Properties();
//			ins = new FileInputStream(this.getClass().getResource("/").getPath()+FILE_NAME);
//			ins = getClass().getResourceAsStream(FILE_NAME);
			ins = GetFixedPasswordUtil.class.getClassLoader().getResourceAsStream(FILE_NAME);
			properties.load(ins);
			saikuUserPassword = properties.getProperty(SAIKU_USER_PASSWORD);
			logger.debug("GetFixedPasswordUtil - getSaikuUserPassword ,read the properties file,password value is:"+saikuUserPassword);
		}catch(Exception e){
			logger.debug("GetFixedPasswordUtil - getSaikuUserPassword failed, Caused by:"+e);
			e.printStackTrace();
		}finally{
			if(ins != null){
				try{
					ins.close();
				}catch(Exception e){
					logger.debug("GetFixedPasswordUtil - getSaikuUserPassword failed, Caused by:"+e);
					e.printStackTrace();
				}
			}
		}
		return saikuUserPassword;
		
	}

	
	/*public static void main(String[] args) throws RemoteException {
		GetFixedPasswordUtil a = new GetFixedPasswordUtil();
//		String url="http://10.28.84.138/iModule-ws/services/um-soa";
		String result  = a.getSaikuUserPassword();
		System.out.println("result："+result);
		
		UmSoaPortTypeProxy um = new UmSoaPortTypeProxy();
		UmLoginResult  result1 = um.umLogin("H0194", "111");
		System.out.println("Status："+result1.getResultStatus());
		System.out.println("ErroCode："+result1.getErrCode());
		System.out.println("ErroCode："+result1.getOpt());
	}*/
} 
 
