import { defineConfig } from '@umijs/max';

export default defineConfig({
  antd: {},
  model: {},
  request: {},
  mfsu: false,
  layout: {
    title: 'IdentityServer 管理后台',
    locale: false,
    layout: 'mix',
  },
  proxy: {
    '/api': {
      target: 'https://localhost:5002',
      changeOrigin: true,
      secure: false,
    },
  },
  routes: [
    {
      path: '/',
      redirect: '/clients',
    },
    {
      name: '客户端管理',
      path: '/clients',
      component: './Clients',
      icon: 'AppstoreOutlined',
    },
    {
      name: 'API 资源',
      path: '/api-resources',
      component: './ApiResources',
      icon: 'ApiOutlined',
    },
    {
      name: 'API 作用域',
      path: '/api-scopes',
      component: './ApiScopes',
      icon: 'SafetyOutlined',
    },
    {
      name: 'Identity 资源',
      path: '/identity-resources',
      component: './IdentityResources',
      icon: 'UserOutlined',
    },
  ],
});