import { defineConfig } from '@umijs/max';

export default defineConfig({
  antd: {},
  model: {},
  request: {},
  mfsu: false,
  layout: {
    title: 'IdentityServer Admin',
    locale: false,
  },
  proxy: {
    '/api': {
      target: 'http://localhost:5000',
      changeOrigin: true,
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
