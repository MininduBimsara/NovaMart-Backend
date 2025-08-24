package com.ecommerce.filter;

import jakarta.servlet.*;
import java.io.IOException;

public class RateLimitingFilter implements Filter {
    private int maxRequests;
    private int timeWindow;
    private int blockDuration;

    public RateLimitingFilter() {}

    public RateLimitingFilter(int maxRequests, int timeWindow, int blockDuration) {
        this.maxRequests = maxRequests;
        this.timeWindow = timeWindow;
        this.blockDuration = blockDuration;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        chain.doFilter(request, response); // dummy passthrough
    }
}
