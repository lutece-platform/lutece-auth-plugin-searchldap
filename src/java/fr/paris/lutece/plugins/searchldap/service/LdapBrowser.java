/*
 * Copyright (c) 2002-2013, Mairie de Paris
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
    private static final String PROPERTY_DN_ATTRIBUTE_FAMILY_NAME = "searchldap.ldap.dn.attributeName.familyName";
    private static final String PROPERTY_DN_ATTRIBUTE_GIVEN_NAME = "searchldap.ldap.dn.attributeName.givenName";
    private static final String PROPERTY_DN_ATTRIBUTE_EMAIL = "searchldap.ldap.dn.attributeName.email";
    private static final String ATTRIBUTE_GUID = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_GUID );
    private static final String ATTRIBUTE_FAMILY_NAME = AppPropertiesService
            .getProperty( PROPERTY_DN_ATTRIBUTE_FAMILY_NAME );
    private static final String ATTRIBUTE_GIVEN_NAME = AppPropertiesService
            .getProperty( PROPERTY_DN_ATTRIBUTE_GIVEN_NAME );
    private static final String ATTRIBUTE_EMAIL = AppPropertiesService.getProperty( PROPERTY_DN_ATTRIBUTE_EMAIL );

    private static final String ATTRIBUTE_FAMILY_NAME_LUTECE_USER = AppPropertiesService
            .getProperty( "searchldap.luteceuser.family_name" );
    private static final String ATTRIBUTE_GIVEN_NAME_LUTECE_USER = AppPropertiesService
            .getProperty( "searchldap.luteceuser.given_name" );
    private static final String ATTRIBUTE_EMAIL_LUTECE_USER = AppPropertiesService
            .getProperty( "searchldap.luteceuser.email" );

    /**
     * Search controls for the user entry search
     */
    private SearchControls _scUserSearchControls;

    /**
     *
     */
    public LdapBrowser( )
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

        String strUserSearchFilter = MessageFormat.format( getUserDnSearchFilterByGUID( ), messageFormatParam );

        try
        {
            _scUserSearchControls = new SearchControls( );
            _scUserSearchControls.setSearchScope( getUserDnSearchScope( ) );
            _scUserSearchControls.setReturningObjFlag( true );
            _scUserSearchControls.setCountLimit( 0 );

            context = LdapUtil.getContext( getInitialContextProvider( ), getProviderUrl( ), getBindDn( ),
                    getBindPassword( ) );

            NamingEnumeration<SearchResult> userResults = LdapUtil.searchUsers( context, strUserSearchFilter,
                    getUserDnSearchBase( ), StringUtils.EMPTY, _scUserSearchControls );

            int count = 0;
            while ( ( userResults != null ) && userResults.hasMore( ) )
            {
                sr = userResults.next( );

                Attributes attributes = sr.getAttributes( );
                String strWssoId = StringUtils.EMPTY;

                if ( attributes.get( ATTRIBUTE_GUID ) != null )
                {
                    strWssoId = attributes.get( ATTRIBUTE_GUID ).get( ).toString( );
                }

                String strLastName = StringUtils.EMPTY;

                if ( attributes.get( ATTRIBUTE_FAMILY_NAME ) != null )
                {
                    strLastName = attributes.get( ATTRIBUTE_FAMILY_NAME ).get( ).toString( );
                }

                String strFirstName = StringUtils.EMPTY;

                if ( attributes.get( ATTRIBUTE_GIVEN_NAME ) != null )
                {
                    strFirstName = attributes.get( ATTRIBUTE_GIVEN_NAME ).get( ).toString( );
                }

                String strEmail = StringUtils.EMPTY;

                if ( attributes.get( ATTRIBUTE_EMAIL ) != null )
                {
                    strEmail = attributes.get( ATTRIBUTE_EMAIL ).get( ).toString( );
                }

                user = new LDAPUser( strWssoId, SecurityService.getInstance( ).getAuthenticationService( ) );
                user.setUserInfo( ATTRIBUTE_FAMILY_NAME_LUTECE_USER, strLastName );
                user.setUserInfo( ATTRIBUTE_GIVEN_NAME_LUTECE_USER, strFirstName );
                user.setEmail( strEmail );
                user.setUserInfo( ATTRIBUTE_EMAIL_LUTECE_USER, strEmail );
                count++;
            }

            // More than one user found (failure)
            if ( count > 1 )
            {
                AppLogService.error( "More than one entry in the ldap for id " + strId );

                return null;
            }

            return user;
        }
        catch ( CommunicationException e )
        {
            AppLogService.error( "Error while searching for user '" + strId + "' in ldap with search filter : "
                    + getDebugInfo( strUserSearchFilter ), e );

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
                AppLogService.error( naming.getMessage( ), naming );
            }
        }
    }

    /**
     * Return info for debugging
     * @param strUserSearchFilter User search filter
     * @return
     */
    private String getDebugInfo( String strUserSearchFilter )
    {
        StringBuffer sb = new StringBuffer( );
        sb.append( "userBase : " );
        sb.append( getUserDnSearchBase( ) );
        sb.append( "\nuserSearch : " );
        sb.append( strUserSearchFilter );

        return sb.toString( );
    }

    /**
     * Get the initial context provider from the properties
     * @return
     */
    private String getInitialContextProvider( )
    {
        return AppPropertiesService.getProperty( PROPERTY_INITIAL_CONTEXT_PROVIDER );
    }

    /**
     * Get the provider url from the properties
     * @return
     */
    private String getProviderUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_PROVIDER_URL );
    }

    /**
     * Get the base user dn from the properties
     * @return
     */
    private String getUserDnSearchBase( )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_BASE );
    }

    /**
     * Get the filter for search by guid
     * @return
     */
    private String getUserDnSearchFilterByGUID( )
    {
        return AppPropertiesService.getProperty( PROPERTY_USER_DN_SEARCH_FILTER_BY_GUID );
    }

    /**
     * Get the user dn search scope
     * @return
     */
    private int getUserDnSearchScope( )
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
    private String getBindDn( )
    {
        return AppPropertiesService.getProperty( PROPERTY_BIND_DN );
    }

    /**
     * Get the bind password
     * @return The password to access the LDAP
     */
    private String getBindPassword( )
    {
        return AppPropertiesService.getProperty( PROPERTY_BIND_PASSWORD );
    }
}
