package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.sentinel.web.filter.CommonFilter;
import org.apache.shiro.spring.boot.sentinel.web.filter.CommonTotalFilter;
import org.springframework.beans.BeansException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnClass(com.alibaba.csp.sentinel.SphU.class)
@ConditionalOnProperty(prefix = ShiroSentinelProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties(ShiroSentinelProperties.class)
public class ShiroSentinelAutoConfiguration implements ApplicationContextAware {
	
	private ApplicationContext applicationContext;
	
	@Bean("origin-sentinel")
    protected FilterRegistrationBean<CommonFilter> commonFilter() throws Exception {
        FilterRegistrationBean<CommonFilter> registration = new FilterRegistrationBean<CommonFilter>();
        registration.setFilter(new CommonFilter());
        registration.setEnabled(false); 
        return registration;
    }
	
	@Bean("total-sentinel")
    protected FilterRegistrationBean<CommonTotalFilter> commonTotalFilter() throws Exception {
        FilterRegistrationBean<CommonTotalFilter> registration = new FilterRegistrationBean<CommonTotalFilter>();
        registration.setFilter(new CommonTotalFilter());
	    registration.setEnabled(false); 
	    return registration;
    }
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}
	
}
 