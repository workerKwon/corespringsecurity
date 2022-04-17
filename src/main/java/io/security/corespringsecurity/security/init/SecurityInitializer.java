package io.security.corespringsecurity.security.init;

import io.security.corespringsecurity.service.RoleHierarchyService;
import io.security.corespringsecurity.service.impl.RoleHierarchyServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

/**
 * DB로부터 계층권한 정보를 가져와서 포맷팅된 RoleHierarchyImple에 넣어준다.
 * ApplicationRunner를 사용해서 Spring이 초기화 될 때 작업하도록 한다.
 */
@Component
public class SecurityInitializer implements ApplicationRunner {

    @Autowired
    private RoleHierarchyService roleHierarchyService;

    @Autowired
    private RoleHierarchyImpl roleHierarchy;

    /**
     * 포맷팅된 계층권한 데이터를 roleHierarchy에 넣어준다.
     */
    @Override
    public void run(ApplicationArguments args) throws Exception {
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        roleHierarchy.setHierarchy(allHierarchy);
    }
}
