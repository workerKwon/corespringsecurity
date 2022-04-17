package io.security.corespringsecurity.security.metadatasource;

import io.security.corespringsecurity.security.service.SecurityResourceService;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * DB에서 가져온 자원 인가 정보를 담고, 유저 요청과 매칭해서 권한 정보를 반환하는 클래스
 */
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {


    /**
     * ConfigAttribute: 권한 정보 객체
     * 자원과 권한 정보가 매핑된 객체
     */
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();

    private SecurityResourceService securityResourceService;

    public UrlFilterInvocationSecurityMetadataSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourcesMap, SecurityResourceService securityResourceService) {
        this.requestMap = resourcesMap;
        this.securityResourceService = securityResourceService;
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) {

        /**
         * 사용자가 요청하는 요청 객체
         */
        HttpServletRequest request = ((FilterInvocation) object).getRequest();

        // 임의로 준 url 자원에 따른 권한
//        requestMap.put(new AntPathRequestMatcher("/mypage"), Arrays.asList(new SecurityConfig("ROLUE_USER")));

        /**
         * 디비에서 가져온 URL 자원 인가 정보와 사용자 요청 정보가 매치되면 DB에서 가져온 권한 정보를 추출해서 반환
         */
        if(requestMap != null){
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()){
                RequestMatcher matcher = entry.getKey();
                if(matcher.matches(request)){
                    return entry.getValue();
                }
            }
        }

        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    /**
     * 자원-권한 데이터가 업데이트 되면 그 업데이트된 자원을 매핑해서 requestMap에 넣어준다.
     */
    public void reload() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();// 매핑한 최종 결과.
        Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();

        requestMap.clear();

        while (iterator.hasNext()) {
            Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
            requestMap.put(entry.getKey(), entry.getValue());
        }
    }
}
