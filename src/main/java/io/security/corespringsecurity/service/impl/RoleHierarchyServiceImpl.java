package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Iterator;
import java.util.List;

@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    /**
     * 권한들을 계층 구조로 포맷팅 한다.
     */
    public String findAllHierarchy() {
        List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();

        Iterator<RoleHierarchy> iterator = rolesHierarchy.iterator();
        StringBuilder concatedRoles = new StringBuilder();
        while (iterator.hasNext()) {
            RoleHierarchy roleHierarchy = iterator.next();
            if(roleHierarchy.getParentName() != null) {
                concatedRoles.append(roleHierarchy.getParentName().getChildName());
                concatedRoles.append(" > ");
                concatedRoles.append(roleHierarchy.getChildName());
                concatedRoles.append("\n");
            }
        }

        return concatedRoles.toString();
    }
}
