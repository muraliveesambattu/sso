import React, { lazy, Suspense, useContext } from 'react';
import { Switch, Route, Redirect } from 'react-router-dom';
import PropTypes from 'prop-types'
import Loading from 'components/shared-components/Loading'
import { getLoginType } from 'auth/FirebaseAuth'
import { AuthContext } from 'auth/AuthProvider'
import { LOGIN_TYPE } from 'redux/constants/Auth'

export const AppViews = ({ match }) => {
  const context = useContext(AuthContext)
  console.log('login type:- ', getLoginType(context?.currentUser))
  return (
    <Suspense fallback={<Loading cover="page" />}>
      <Switch>
        <Route
          path={`${match.url}/login/legacy`}
          component={lazy(() => import(`./authentication/login`))}
        />
        <Route
          path={`${match.url}/login`}
          component={lazy(() => import(`./authentication/login-v2`))}
        />
        <Route
          path={`${match.url}/userLogin`}
          component={lazy(() => import(`./authentication/login-2`))}
        />
        <Route
          path={`${match.url}/oidc/callback`}
          component={lazy(() => import(`./authentication/oidc-callback`))}
        />
        <Route
          path={`${match.url}/forgot-password`}
          component={lazy(() => import(`./authentication/forgot-password`))}
        />
        <Route
          path={`${match.url}/error-1`}
          component={lazy(() => import(`./errors/error-page-1`))}
        />
        <Route
          path={`${match.url}/error-2`}
          component={lazy(() => import(`./errors/error-page-2`))}
        />
        <Redirect
          from={`${match.url}`}
          to={
            window.location.href.match('legacy') || localStorage.getItem(LOGIN_TYPE) == '1'
              ? `${match.url}/login/legacy`
              : `${match.url}/login`
          }
        />
      </Switch>
    </Suspense>
  )
}

AppViews.propTypes = {
  match: PropTypes.object.isRequired,
}
