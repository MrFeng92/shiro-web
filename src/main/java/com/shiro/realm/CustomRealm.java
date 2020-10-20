package com.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CustomRealm extends AuthorizingRealm
{
    Map<String, String> map = new HashMap<>();

    {
        map.put("Mark", "98208ac241fb7c26ad164610e9484663");
        super.setName("customRealm");
    }

    /**
     * 权限管理
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection)
    {
        //1.获取用户名
        String username = (String) principalCollection.getPrimaryPrincipal();
        //2.从数据库或缓存中获取角色数据
        Set<String> roles = getRolesByUsername(username);
        //3.从数据库或缓存中获取权限数据
        Set<String> permissions = getpermissionsByUsername(username);
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setStringPermissions(permissions);
        simpleAuthorizationInfo.setRoles(roles);
        return simpleAuthorizationInfo;
    }

    private Set<String> getpermissionsByUsername(String username)
    {
        Set<String> permissions = new HashSet<>();
        permissions.add("user:add");
        permissions.add("user:update");
        permissions.add("user:select");
        return permissions;
    }

    private Set<String> getRolesByUsername(String username)
    {
        Set<String> roles = new HashSet<>();
        roles.add("admin");
        roles.add("user");
        return roles;
    }

    /**
     * 认证管理
     *
     * @param authenticationToken 主体传过来的认证信息
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException
    {
        //1.从主体传过来的信息中获取用户名
        String username = (String) authenticationToken.getPrincipal();

        //2.通过用户名到数据库获取凭证
        String password = getPasswordByUsername(username);
        if (password == null)
        {
            return null;
        }
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo("Mark", password, "customRealm");
        info.setCredentialsSalt(ByteSource.Util.bytes("Mark"));//添加加密盐
        return info;
    }

    /**
     * 模拟数据库查询密码
     *
     * @param username
     * @return
     */
    private String getPasswordByUsername(String username)
    {
        return map.get(username);
    }

    public static void main(String[] args)
    {
        Md5Hash md5Hash = new Md5Hash("1234567", "Mark", 2);
        System.out.println("md5Hash = " + md5Hash);
    }
}
