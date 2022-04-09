package io.security.corespringsecurity.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 인증 성공 후 후속 작업을 설정한 클래스
 */
@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    /**
     * 세션을 담고 있는 객체를 꺼내올 수 있는 객체
     */
    private RequestCache requestCache = new HttpSessionRequestCache();

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * FilterChain 파라미터를 담으면 다르게 동작한다.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        setDefaultTargetUrl("/");

        /**
         * 사용자의 요청 정보를 담고 있는 객체
         */
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        /**
         * 인증을 성공하고 나서 사용자의 요청 정보가 저장된 것이 있다면 가려고 했던 url로 보낸다.
         * 인증을 성공하고 나서 사용자의 요청을 저장해놓은게 없다면 그냥 defaultUrl로 보낸다.
         */
        if(savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request, response, targetUrl);
        } else {
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }

    }
}
