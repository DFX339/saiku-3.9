package org.saiku.web.rest.resources;

	import org.saiku.service.ISessionService;
	import org.saiku.service.user.UserService;
	import org.slf4j.Logger;
	import org.slf4j.LoggerFactory;
	import org.springframework.security.core.Authentication;
	import org.springframework.security.core.context.SecurityContextHolder;
	import org.springframework.stereotype.Component;

	import javax.servlet.http.HttpServletRequest;
	import javax.servlet.http.HttpServletResponse;
	import javax.ws.rs.GET;
	import javax.ws.rs.Path;
	import javax.ws.rs.core.Context;
	import java.io.IOException;
	import java.util.Map;

	/**
	 * Created by fc on 16-8-10.
	 */
	@Component
	@Path("/casLogin")
	public class CasLoginController {
	    private static final Logger log = LoggerFactory.getLogger(CasLoginController.class);

	    private ISessionService sessionService;
	    private UserService userService;

	    public void setSessionService(ISessionService sessionService) {
	        this.sessionService = sessionService;
	    }

	    public void setUserService(UserService userService) {
	        this.userService = userService;
	    }
	    @GET
	    public void casLogin(@Context HttpServletRequest req, @Context HttpServletResponse response) throws IOException {
	        Map<String, Object> sess = null;
	        try {
	            sess = sessionService.getSession();
	            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
	            //session里面没有authid，而SpringSecurity里面已经授权。
	            log.debug("authid:"+sess.get("authid")+" isAuthenticated:"+auth.isAuthenticated());
	            if (sess.get("authid") == null && auth.isAuthenticated()) {
	                //则为CAS登陆，登陆sessionService
	                sessionService.login(req,null,null);
	                sess = sessionService.getSession();
	            }
	            response.sendRedirect("/");
	        } catch (Exception e) {
	            response.sendError(500,e.getLocalizedMessage());
	        }
	    }
	}
