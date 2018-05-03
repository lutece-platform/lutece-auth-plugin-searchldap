/*
 * Copyright (c) 2002-2017, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.searchldap.service;

import fr.paris.lutece.plugins.searchldap.business.LDAPUser;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.security.SecurityService;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

import org.apache.commons.lang.StringUtils;

import java.text.MessageFormat;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;


/**
 * Data authentication module for admin authentication
 */
public class LdapBrowser
{
    /**
     * Name of the bean of this service
     */
    public static final String BEAN_NAME = "searchldap.ldapBrowser";

    // ldap
    private static final String PROPERTY_INITIAL_CONTEXT_PROVIDER = "searchldap.ldap.initialContextProvider";
    private static final String PROPERTY_PROVIDER_URL = "searchldap.ldap.connectionUrl";
    private static final String PROPERTY_BIND_DN = "searchldap.ldap.connectionName";
    private static final String PROPERTY_BIND_PASSWORD = "searchldap.ldap.connectionPassword";
    private static final String PROPERTY_USER_DN_SEARCH_BASE = "searchldap.ldap.userBase";
    private static final String PROPERTY_USER_DN_SEARCH_FILTER_BY_GUID = "searchldap.ldap.userSearch.guid";
    private static final String PROPERTY_USER_SUBTREE = "searchldap.ldap.userSubtree";
    private static final String PROPERTY_DN_ATTRIBUTE_GUID = "searchldap.ldap.dn.attributeName.guid";
    private static final String PROPERTY_DN_ATTRIBUTE_LIST = "searchldap.ldap.dn.attributeName.list";
    private static final String PROPERTY_DN_ATTRIBUTE_EMAIL = "searchldap.ldap.dn.attributeName.email";
    private static final String PROPERTY_DN_ATTRIBUTE_PREFIXE = "searchldap.ldap.dn.attributeName.";
    private static final String PROPERTY_LUTECE_USER_ATTRIBUTE_PROFIXE = "searchldap.luteceuser.attribute.";

    // Attributes
    private static final String ATTRIBUTE_GUID = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_GUID );
    private static final String ATTRIBUTE_EMAIL = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_EMAIL );
    private static final String ATTRIBUTE_EMAIL_LUTECE_USER = AppPropertiesService.getProperty( 
            "searchldap.luteceuser.attribute.email" );
    private static final String CONSTANT_COMMA = ",";
    private volatile Map<String, String> _mapLdapLuteceUser;

    /**
     * Creates a new LDAP browser
     */
    public LdapBrowser(  )
    {
    }

    /**
     * Return a user given its guid
     * @param strId the guid
     * @return the corresponding user
     */
    public LuteceUser getUserPublicData( String strId )
    {
        LDAPUser user = null;
        SearchResult sr = null;
        Object[] messageFormatParam = new Object[1];

        DirContext context = null;

        messageFormatParam[0] = strId;

        String strUserSearchFilter = MessageFormat.format( getUserDnSearchFilterByGUID(  ), messageFormatParam );

        try
        {
            SearchControls scUserSearchControls = new SearchControls(  );
            scUserSearchControls.setSearchScope( getUserDnSearchScope(  ) );
            scUserSearchControls.setReturningObjFlag( true );
            scUserSearchControls.setCountLimit( 1 );

            context = LdapUtil.getContext( getInitialContextProvider(  ), getProviderUrl(  ), getBindDn(  ),
                    getBindPassword(  ) );

            NamingEnumeration<SearchResult> userResults = LdapUtil.searchUsers( context, strUserSearchFilter,
                    getUserDnSearchBase(  ), StringUtils.EMPTY, scUserSearchControls );

            while ( ( userResults != null ) && userResults.hasMore(  ) )
            {
                sr = userResults.next(  );

                Attributes attributes = sr.getAttributes(  );
                String strWssoId = StringUtils.EMPTY;

                if ( attributes.get( ATTRIBUTE_GUID ) != null )
                {
                    strWssoId = attributes.get( ATTRIBUTE_GUID ).get(  ).toString(  );
                }

                String strEmail = StringUtils.EMPTY;

                if ( attributes.get( ATTRIBUTE_EMAIL ) != null )
                {
                    strEmail = attributes.get( ATTRIBUTE_EMAIL ).get(  ).toString(  );
                }

                user = new LDAPUser( strWssoId, SecurityService.getInstance(  ).getAuthenticationService(  ) );
                user.setEmail( strEmail );
                user.setUserInfo( ATTRIBUTE_EMAIL_LUTECE_USER, strEmail );

                Map<String, String> mapLdapLuteceUserAttributes = getMapLdapLuteceUser(  );

                for ( Entry<String, String> entry : mapLdapLuteceUserAttributes.entrySet(  ) )
                {
                    if ( attributes.get( entry.getKey(  ) ) != null )
                    {
                        user.setUserInfo( entry.getValue(  ), attributes.get( entry.getKey(  ) ).get(  ).toString(  ) );
                    }
                }
            }

            return user;
        }
        catch ( CommunicationException e )
        {
            AppLogService.error( "Error while searching for user '" + strId + "' in ldap with search filter : " +
                getDebugInfo( strUserSearchFilter ), e );

            return null;
        }
        catch ( NamingException e )
        {
            AppLogService.error( "Error while searching for user in ldap ", e );

            return null;
        }
        finally
        {
            try
            {
                LdapUtil.freeContext( context );
            }
            catch ( NamingException naming )
            {
                AppLogService.error( naming.getMessage(  ), naming );
            }
        }
    }

    /**
     * Return info for debugging
     * @param strUserSearchFilter User search filter
     * @return The debug info
     */
    private String getDebugInfo( String strUserSearchFilter )
    {
        StringBuffer sb = new StringBuffer(  );
        sb.append( "userBase : " );
        sb.append( getUserDnSearchBase(  ) );
        sb.append( "\nuserSearch : " );
        sb.append( strUserSearchFilter );

        return sb.toString(  );
    }

    /**
     * Get the initial context provider from the properties
     * @return The initial context provider
     */
    private String getInitialContextProvider(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_INITIAL_CONTEXT_PROVIDER );
    }

    /**
     * Get the provider url from the properties
     * @return The provider URL
     */
    private String getProviderUrl(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_PROVIDER_URL );
    }

    /**
     * Get the base user dn from the properties
     * @return The DN search base
     */
    private String getUserDnSearchBase(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_BASE );
    }

    /**
     * Get the filter for search by guid
     * @return The guid search filter
     */
    private String getUserDnSearchFilterByGUID(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_FILTER_BY_GUID );
    }

    /**
     * Get the user dn search scope
     * @return The search scope
     */
    private int getUserDnSearchScope(  )
    {
        String strSearchScope = AppPropertiesService.getProperty( PROPERTY_USER_SUBTREE );

        if ( Boolean.parseBoolean( strSearchScope ) )
        {
            return SearchControls.SUBTREE_SCOPE;
        }

        return SearchControls.ONELEVEL_SCOPE;
    }

    /**
     * get the bind dn
     * @return the user name to access the LDAP
     */
    private String getBindDn(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_BIND_DN );
    }

    /**
     * Get the bind password
     * @return The password to access the LDAP
     */
    private String getBindPassword(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_BIND_PASSWORD );
    }

    /**
     * Get a map containing an association between MDAP attributes and lutece
     * user attributes. Each attribute of the map should be queried to the LDAP.
     * @return The map
     */
    private synchronized Map<String, String> getMapLdapLuteceUser(  )
    {
        if ( _mapLdapLuteceUser == null )
        {
            String strListAttributes = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_LIST );

            if ( StringUtils.isNotEmpty( strListAttributes ) )
            {
                String[] strArrayListAttributes = strListAttributes.split( CONSTANT_COMMA );
                _mapLdapLuteceUser = new HashMap<String, String>( strArrayListAttributes.length );

                for ( String strAttribute : strArrayListAttributes )
                {
                    String strLdapAttribute = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_PREFIXE +
                            strAttribute );
                    String strLuteceUserAttribute = AppPropertiesService.getProperty( PROPERTY_LUTECE_USER_ATTRIBUTE_PROFIXE +
                            strAttribute );

                    if ( StringUtils.isNotEmpty( strLdapAttribute ) &&
                            StringUtils.isNotEmpty( strLuteceUserAttribute ) )
                    {
                        _mapLdapLuteceUser.put( strLdapAttribute, strLuteceUserAttribute );
                    }
                }
            }
            else
            {
                _mapLdapLuteceUser = new HashMap<String, String>(  );
            }
        }

        return _mapLdapLuteceUser;
    }
}
