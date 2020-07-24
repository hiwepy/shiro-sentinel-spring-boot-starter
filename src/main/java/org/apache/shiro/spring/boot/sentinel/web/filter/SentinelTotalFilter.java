/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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

import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.web.filter.AccessControlFilter;

import com.alibaba.csp.sentinel.Entry;
import com.alibaba.csp.sentinel.SphU;
import com.alibaba.csp.sentinel.Tracer;
import com.alibaba.csp.sentinel.adapter.servlet.callback.WebCallbackManager;
import com.alibaba.csp.sentinel.adapter.servlet.util.FilterUtil;
import com.alibaba.csp.sentinel.context.ContextUtil;
import com.alibaba.csp.sentinel.slots.block.BlockException;

/**                
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class SentinelTotalFilter extends AccessControlFilter {

    public static final String TOTAL_URL_REQUEST = "total-url-request";
	
	@Override
	public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		
		HttpServletRequest sRequest = WebUtils.toHttp(request);
        String target = FilterUtil.filterTarget(sRequest);
        target = WebCallbackManager.getUrlCleaner().clean(target);

        Entry entry = null;
        try {
            ContextUtil.enter(target);
            entry = SphU.entry(TOTAL_URL_REQUEST);
            super.doFilterInternal(request, response, chain);
        } catch (BlockException e) {
            HttpServletResponse sResponse = (HttpServletResponse)response;
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
