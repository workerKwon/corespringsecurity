package io.security.corespringsecurity.service;

import io.security.corespringsecurity.security.aop.CustomMethodSecurityInterceptor;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.support.DefaultSingletonBeanRegistry;
import org.springframework.boot.web.servlet.context.AnnotationConfigServletWebServerApplicationContext;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;

import java.util.Arrays;
import java.util.List;

/**
 * 실시간 메소드 보안을 적용할 수 있도록 하는 클래스
 */
@Component
public class MethodSecurityService {

    private MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource;
    private AnnotationConfigServletWebServerApplicationContext applicationContext;
    private CustomMethodSecurityInterceptor methodSecurityInterceptor;

    public MethodSecurityService(MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource, AnnotationConfigServletWebServerApplicationContext applicationContext, CustomMethodSecurityInterceptor methodSecurityInterceptor) {
        this.mapBasedMethodSecurityMetadataSource = mapBasedMethodSecurityMetadataSource;
        this.applicationContext = applicationContext;
        this.methodSecurityInterceptor = methodSecurityInterceptor;
    }


    /**
     * DB에 자원정보를 업데이트 했을 때, 그 자원(메소드)에 해당하는 프록시 객체를 생성하고 어드바이스를 등록하여 메소드 보안이 적용될 수 있도록 하는 메소드
     */
    public void addMethodSecured(String className, String roleName) throws Exception{

        int lastDotIndex = className.lastIndexOf(".");
        String methodName = className.substring(lastDotIndex + 1);
        String typeName = className.substring(0, lastDotIndex);
        Class<?> type = ClassUtils.resolveClassName(typeName, ClassUtils.getDefaultClassLoader());
        String beanName = type.getSimpleName().substring(0, 1).toLowerCase() + type.getSimpleName().substring(1);

        ProxyFactory proxyFactory = new ProxyFactory();
        proxyFactory.setTarget(type.getDeclaredConstructor().newInstance());
        proxyFactory.addAdvice(methodSecurityInterceptor);
        Object proxy = proxyFactory.getProxy();

        List<ConfigAttribute> attr = Arrays.asList(new SecurityConfig(roleName));

        /**
         * 메소드나 클래스와 권한 정보를 전달해서 인가처리를 할 때 클래스로부터 권한 목록을 추출할 수 있도록 한다.
         */
        mapBasedMethodSecurityMetadataSource.addSecureMethod(type,methodName, attr);


        DefaultSingletonBeanRegistry registry = (DefaultSingletonBeanRegistry)applicationContext.getBeanFactory();
        registry.destroySingleton(beanName);
        registry.registerSingleton(beanName, proxy);

    }

    /**
     * 적용된 메소드보안을 해제하고자 할 때 실행
     */
    public void removeMethodSecured(String className) throws Exception{

        int lastDotIndex = className.lastIndexOf(".");
        String typeName = className.substring(0, lastDotIndex);
        Class<?> type = ClassUtils.resolveClassName(typeName, ClassUtils.getDefaultClassLoader());
        String beanName = type.getSimpleName().substring(0, 1).toLowerCase() + type.getSimpleName().substring(1);
        Object newInstance = type.getDeclaredConstructor().newInstance();

        DefaultSingletonBeanRegistry registry = (DefaultSingletonBeanRegistry)applicationContext.getBeanFactory();
        Object singleton = registry.getSingleton(beanName);
        registry.destroySingleton(beanName);
        registry.registerSingleton(beanName, newInstance);

    }
}
