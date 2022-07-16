package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Arrays;
import java.util.List;

@Order(1)
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final AuthenticationDetailsSource authenticationDetailsSource;

    private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;

    private final AuthenticationFailureHandler customAuthenticationFailureHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 보안 필터 자체를 걸치지 않음
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/users", "user/login/**", "/login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
        .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .defaultSuccessUrl("/")
                .authenticationDetailsSource(authenticationDetailsSource)
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll();
        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
        .and()
                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class);


    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Bean
    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
        filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
        return filterSecurityInterceptor;
    }

    private AccessDecisionManager affirmativeBased() {
        return new AffirmativeBased(getAccessDecisionVoters());
    }

    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
        return Arrays.asList(new RoleVoter());
    }

    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() {
        return new UrlFilterInvocationSecurityMetadataSource();
    }

}
