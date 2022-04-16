package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.repository.RoleRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * 권한과 자원이 매핑된 객체를 만들어야 한다.
 */
public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    /**
     * 디비로부터 권한과 자원 정보를 가져와서 매핑한다.
     * @return LinkedHashMap<RequestMatcher, List<ConfigAttribute>>
     */
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {

        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();
        resourcesList.forEach(resources -> {
            List<ConfigAttribute> configAttributes = new ArrayList<>();
            // resource에 엮여있는 권한들을 List로 묶는다.
            resources.getRoleSet().forEach(role -> {
                configAttributes.add(new SecurityConfig(role.getRoleName()));
                result.put(new AntPathRequestMatcher(resources.getResourceName()), configAttributes);
            });
//            result.put(new AntPathRequestMatcher(resources.getResourceName()), configAttributes);
        });

        return result;
    }

}
