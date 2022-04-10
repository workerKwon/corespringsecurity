package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Ajax 인증 처리를 담당하는 필터
 */
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login")); // 이 url로 요청이 오지 않으면 필터가 실행되지 않는다.
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {

        /**
         * 요청의 헤더에 X-Requested-With 값이 XMLHttpRequest라는 임의의 값이라면 Ajax 요청으로 간주한다.
         */
        if (!isAjax(httpServletRequest)) {
            throw new IllegalStateException("Authentication is not supported");
        }

        /**
         * 읽어온 요청 정보를 AccountDto 클래스 타입으로 받는다.
         */
        AccountDto accountDto = objectMapper.readValue(httpServletRequest.getReader(), AccountDto.class);

        if(StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
            throw new IllegalArgumentException("Username or Password is empty");
        }

        /**
         * AjaxToken을 만든다.
         */
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        /**
         * 인증 정보를 생성해서 반환한다.
         */
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    private boolean isAjax(HttpServletRequest httpServletRequest) {

        if ("XMLHttpRequest".equals(httpServletRequest.getHeader("X-Requested-With"))) {
            return true;
        }

        return false;
    }
}
