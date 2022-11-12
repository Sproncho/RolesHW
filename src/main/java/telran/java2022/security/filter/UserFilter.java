package telran.java2022.security.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

@Component
@RequiredArgsConstructor
@Order(20)
public class UserFilter implements Filter {
    final UserAccountRepository userAccountRepository;
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;
        String pathUsername = request.getServletPath().split("/")[3]; UserAccount userAccount = userAccountRepository
                .findById(request.getUserPrincipal().getName()).get();
        if(checkDeleteEndPoint(request.getMethod(),request.getServletPath())){
            if(!(userAccount.getRoles().contains("Administrator") &&
            request.getUserPrincipal().getName().equalsIgnoreCase(pathUsername))){
                response.sendError(403);
                return;
            }
        }
        if(checkDeleteEndPoint(request.getMethod(),request.getServletPath())){
            if(!request.getUserPrincipal().getName().equalsIgnoreCase(pathUsername)){
                response.sendError(403);
                return;
            }
        }
    }
    private boolean checkDeleteEndPoint(String method, String servletPath) {
        return (method.equalsIgnoreCase("DELETE") && servletPath.matches("/account/user/\\w+/?"));
    }
    private boolean checkPutEndPoint(String method, String servletPath) {
        return (method.equalsIgnoreCase("PUT") && servletPath.matches("/account/user/\\w+/?"));
    }
}
