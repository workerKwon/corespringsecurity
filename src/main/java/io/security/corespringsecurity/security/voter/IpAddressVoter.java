package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.security.service.SecurityResourceService;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;

public class IpAddressVoter implements AccessDecisionVoter<Object> {

    private SecurityResourceService securityResourceService;

    public IpAddressVoter(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    /**
     * authentication 인증정보, object 요청정보, attributes 접근에 필요한 권한 정보
     */
    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

        WebAuthenticationDetails details =(WebAuthenticationDetails) authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();// 사용자의 Ip 주소

        List<String> accessIpList = securityResourceService.getAccessIpList(); // 허용된 Ip 주소

        int result = ACCESS_DENIED;
        for (String ipAddress : accessIpList) {
            if (remoteAddress.equals(ipAddress)) {
                /**
                 * IP 심사를 통과하더라도 권한 심사 등의 인가 심사는 계속 진행 되어야 하기 때문에
                 * ACCESS_GRANTED가 아닌 ACCESS_ABSTAIN을 줘야한다.
                 */
                return ACCESS_ABSTAIN;
            }
        }

        /**
         * 허용이 안됐다면 더 이상의 인가 심사를 진행하면 안되기 때문에 바로 exception을 띄워서 처리한다.
         */
        if (result == ACCESS_DENIED) {
            throw new AccessDeniedException("Invalid IpAddress");
        }

        return result;
    }
}
