package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AjaxAuthenticationProvider ajaxAuthenticationProvider;

    @Autowired
    private AjaxLoginAuthenticationEntryPoint ajaxLoginAuthenticationEntryPoint;

    @Autowired
    private AjaxAccessDeniedHandler ajaxAccessDeniedHandler;

    @Autowired
    private AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler;

    @Autowired
    private AjaxAuthenticationFailureHandler ajaxAuthenticationFailureHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/messages").hasRole("USER")
                .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                .accessDeniedHandler(ajaxAccessDeniedHandler)
                .authenticationEntryPoint(ajaxLoginAuthenticationEntryPoint);

        http.csrf().disable();

        customConfigureAjax(http);
    }

    private void customConfigureAjax(HttpSecurity http) throws Exception {
        http
                .apply(new AjaxLoginConfigurer<>())
                .successHandlerAjax(ajaxAuthenticationSuccessHandler)
                .failureHandlerAjax(ajaxAuthenticationFailureHandler);
    }
}
