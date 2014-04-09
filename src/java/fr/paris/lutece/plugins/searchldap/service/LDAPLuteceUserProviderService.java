/*
 * Copyright (c) 2002-2014, Mairie de Paris
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

import fr.paris.lutece.portal.service.security.ILuteceUserProviderService;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

import org.apache.commons.lang.StringUtils;

import java.util.regex.Pattern;


/**
 * Service to get a LuteceUser from a LDAP
 */
public class LDAPLuteceUserProviderService implements ILuteceUserProviderService
{
    private static final String PROPERTY_GUID_REGEX = "searchldap.guid.regularexpression";
    private static final String PROPERTY_STORE_USERS_FOUND_IN_CACHE = "searchldap.cache.storeUsersNotFoundInCache";

    private volatile LdapBrowser _ldapBrowser;

    private Boolean _bStoreUsersNotFoundInCache;

    /**
     * {@inheritDoc}
     */
    @Override
    public LuteceUser getLuteceUserFromName( String strName )
    {
        String strRegEx = AppPropertiesService.getProperty( PROPERTY_GUID_REGEX );
        if ( StringUtils.isEmpty( strRegEx ) || Pattern.matches( strRegEx, strName ) )
        {
            if ( getStoreUsersNotFoundInCache( )
                    && LDAPUserNotFoundCacheService.getService( ).getFromCache(
                            LDAPUserNotFoundCacheService.getCacheKeyFromUserName( strName ) ) != null )
            {
                return null;
            }
            LuteceUser user = getLDAPBrowser( ).getUserPublicData( strName );
            if ( user == null && getStoreUsersNotFoundInCache( ) )
            {
                LDAPUserNotFoundCacheService.getService( ).putInCache(
                        LDAPUserNotFoundCacheService.getCacheKeyFromUserName( strName ), strName );
            }
            return user;
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canUsersBeCached( )
    {
        return true;
    }

    /**
     * Get the LDAP browser
     * @return The LDAP browser
     */
    private LdapBrowser getLDAPBrowser( )
    {
        if ( _ldapBrowser == null )
        {
            _ldapBrowser = SpringContextService.getBean( LdapBrowser.BEAN_NAME );
        }
        return _ldapBrowser;
    }

    /**
     * Check if users that was not found in the LDAP should be stored in cache
     * @return True if users not found in the LDAP should be stored in cache,
     *         false otherwise
     */
    private boolean getStoreUsersNotFoundInCache( )
    {
        if ( _bStoreUsersNotFoundInCache == null )
        {
            _bStoreUsersNotFoundInCache = new Boolean( Boolean.parseBoolean( AppPropertiesService
                    .getProperty( PROPERTY_STORE_USERS_FOUND_IN_CACHE ) ) );
        }
        return _bStoreUsersNotFoundInCache;
    }
}
