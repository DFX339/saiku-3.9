package org.saiku.service.util;

import java.rmi.RemoteException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.imodule.ws.soa.um.UmSoaPortTypeProxy;
import com.imodule.ws.soa.um.result.xsd.UmLoginResult;
/**
 * Use UM system login interface to validate userid and password
 * @author S0111
 *
 */
public class UMLoginWSUtil {

	protected final Log logger = LogFactory.getLog(getClass());
	
	public UmLoginResult getUmLoginWS(String username ,String password){
		UmSoaPortTypeProxy um = new UmSoaPortTypeProxy();
		UmLoginResult result = null;
		try {
			result = um.umLogin(username, password);
			logger.debug("UMLoginWSUtil - getUmLoginWS,validate userid and password by UM interface  success !!!");
		} catch (RemoteException e) {
			logger.debug("UMLoginWSUtil - getUmLoginWS,validate userid and password by UM interface  failed !!!,Caused by:"+e);
			e.printStackTrace();
		}
		return result;
	}
}
