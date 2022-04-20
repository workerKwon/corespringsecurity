package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.security.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;

import java.util.LinkedHashMap;
import java.util.List;

public class MethodResourcesFactoryBean implements FactoryBean<LinkedHashMap<String, List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;

    public MethodResourcesFactoryBean(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    private LinkedHashMap<String, List<ConfigAttribute>> resourceMap;

    @Override
    public LinkedHashMap<String, List<ConfigAttribute>> getObject() {

        if(resourceMap == null) {
            init();
        }
        return resourceMap;
    }

    private void init() {
        resourceMap = securityResourceService.getMethodResourceList();
    }

    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }
}
