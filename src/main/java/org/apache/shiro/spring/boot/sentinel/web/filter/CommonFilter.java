/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.sentinel.web.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.web.filter.AccessControlFilter;

import com.alibaba.csp.sentinel.Entry;
import com.alibaba.csp.sentinel.EntryType;
import com.alibaba.csp.sentinel.SphU;
import com.alibaba.csp.sentinel.Tracer;
import com.alibaba.csp.sentinel.adapter.servlet.callback.RequestOriginParser;
import com.alibaba.csp.sentinel.adapter.servlet.callback.UrlCleaner;
import com.alibaba.csp.sentinel.adapter.servlet.callback.WebCallbackManager;
import com.alibaba.csp.sentinel.adapter.servlet.util.FilterUtil;
import com.alibaba.csp.sentinel.context.ContextUtil;
import com.alibaba.csp.sentinel.slots.block.BlockException;
import com.alibaba.csp.sentinel.util.StringUtil;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class CommonFilter extends AccessControlFilter {

	private static final String EMPTY_ORIGIN = "";
	
	@Override
	public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		
		HttpServletRequest sRequest = (HttpServletRequest)request;
        Entry entry = null;

        try {
        	
            String target = FilterUtil.filterTarget(sRequest);
            // Clean and unify the URL.
            // For REST APIs, you have to clean the URL (e.g. `/foo/1` and `/foo/2` -> `/foo/:id`), or
            // the amount of context and resources will exceed the threshold.
            UrlCleaner urlCleaner = WebCallbackManager.getUrlCleaner();
            if (urlCleaner != null) {
                target = urlCleaner.clean(target);
            }
            
            // Parse the request origin using registered origin parser.
            String origin = parseOrigin(sRequest);

            ContextUtil.enter(target, origin);
            entry = SphU.entry(target, EntryType.IN);

    		super.doFilterInternal(request, response, chain);
    		
        } catch (BlockException e) {
            HttpServletResponse sResponse = (HttpServletResponse)response;
            // Return the block page, or redirect to another URL.
            WebCallbackManager.getUrlBlockHandler().blocked(sRequest, sResponse);
        } catch (IOException e2) {
            Tracer.trace(e2);
            throw e2;
        } catch (ServletException e3) {
            Tracer.trace(e3);
            throw e3;
        } catch (RuntimeException e4) {
            Tracer.trace(e4);
            throw e4;
        } finally {
            if (entry != null) {
                entry.exit();
            }
            ContextUtil.exit();
        }
		
	}
	
	private String parseOrigin(HttpServletRequest request) {
	        RequestOriginParser originParser = WebCallbackManager.getRequestOriginParser();
	        String origin = EMPTY_ORIGIN;
	        if (originParser != null) {
	            origin = originParser.parseOrigin(request);
	            if (StringUtil.isEmpty(origin)) {
	                return EMPTY_ORIGIN;
	            }
	        }
	        return origin;
	    }
	 
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		return true;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return true;
	}
	
}
