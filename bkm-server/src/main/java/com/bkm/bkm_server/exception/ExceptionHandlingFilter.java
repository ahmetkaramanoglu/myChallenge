package com.bkm.bkm_server.exception;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authorization.AuthorizationDeniedException;

import java.security.SignatureException;

public class ExceptionHandlingFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    //dofilter ile aslinda request ve response arasinda bir nevi interceptor gorevi goruyor. yani dogru controllera gitmeden once buradan geciyor.
    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain filterChain)  {
        System.out.println("ExceptionHandlingFilter.doFilter");
        try {
            filterChain.doFilter(servletRequest, servletResponse);
        }catch (Exception e){
            System.out.println("ExceptionHandlingFilter.doFilter: message: " + e.getMessage());
            handleException((HttpServletResponse) servletResponse, e);
        }

    }
    private void handleException(HttpServletResponse response, Exception e){
        //İstemci kimlik doğrulaması başarısız olduğunda kullanılır.
        if(e instanceof SignatureException){
            System.out.println("SignatureException");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
        //İstemci kimlik doğrulaması geçerli olsa da, belirli bir kaynağa erişim yetkisi olmadığında kullanılır.
        else if (e instanceof AuthorizationDeniedException){
            System.out.println("AuthorizationDeniedException");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
        else{
            System.out.println("Exception");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
