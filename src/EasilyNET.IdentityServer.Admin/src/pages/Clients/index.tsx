import { Client, createClient, CreateClientRequest, deleteClient, getApiScopes, getClient, getClients, getIdentityResources, updateClient, UpdateClientRequest } from '@/services/api';
import { PlusOutlined, SafetyCertificateOutlined, SearchOutlined } from '@ant-design/icons';
import { PageContainer } from '@ant-design/pro-components';
import { useRequest } from '@umijs/max';
import { Alert, Button, Card, Col, Form, Input, InputNumber, message, Modal, Popconfirm, Row, Select, Space, Statistic, Switch, Table, Tag, Tooltip, Typography } from 'antd';
import { useCallback, useMemo, useState } from 'react';
import styles from './index.module.css';

const { Text } = Typography;

const grantTypeOptions = [
  { label: 'Authorization Code', value: 'authorization_code' },
  { label: 'Client Credentials', value: 'client_credentials' },
  { label: 'Refresh Token', value: 'refresh_token' },
  { label: 'Device Code', value: 'device_code' },
];

const promptTypeOptions = [
  { label: 'none', value: 'none' },
  { label: 'login', value: 'login' },
  { label: 'consent', value: 'consent' },
  { label: 'select_account', value: 'select_account' },
];

const clientTypeOptions = [
  { label: '机密客户端', value: 0 },
  { label: '公开客户端', value: 1 },
];

export default function ClientsPage() {
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [keyword, setKeyword] = useState('');
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [form] = Form.useForm();
  const watchedClientType = Form.useWatch('clientType', form);

  const { data: clients, loading, refresh } = useRequest(getClients);
  const { data: apiScopes } = useRequest(getApiScopes);
  const { data: identityResources } = useRequest(getIdentityResources);

  const scopeOptions = useMemo(
    () =>
      [...(apiScopes ?? []), ...(identityResources ?? [])].map((scope) => ({
        label: `${scope.name}${scope.displayName ? ` · ${scope.displayName}` : ''}`,
        value: scope.name,
      })),
    [apiScopes, identityResources],
  );

  const filteredClients = useMemo(() => {
    const normalizedKeyword = keyword.trim().toLowerCase();
    if (!normalizedKeyword) {
      return clients ?? [];
    }

    return (clients ?? []).filter((client) => {
      const haystack = [
        client.clientId,
        client.clientName,
        client.description,
        ...(client.allowedGrantTypes ?? []),
        ...(client.authorizationPromptTypes ?? []),
        ...(client.identityProviderRestrictions ?? []),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();

      return haystack.includes(normalizedKeyword);
    });
  }, [clients, keyword]);

  const summary = useMemo(() => {
    const source = clients ?? [];
    return {
      total: source.length,
      enabled: source.filter((item) => item.enabled).length,
      confidential: source.filter((item) => item.clientType === 0).length,
      requireConsent: source.filter((item) => item.requireConsent).length,
    };
  }, [clients]);

  const handleCreate = useCallback(() => {
    setEditingId(null);
    setSubmitError(null);
    form.resetFields();
    form.setFieldsValue({
      enabled: true,
      requirePkce: true,
      requireClientSecret: true,
      requireConsent: false,
      allowRememberConsent: true,
      allowPlainTextPkce: false,
      accessTokenLifetime: 3600,
      refreshTokenLifetime: 86400,
      authorizationCodeLifetime: 300,
      deviceCodeLifetime: 300,
      clientType: 0,
    });
    setModalOpen(true);
  }, [form]);

  const handleEdit = useCallback(
    async (record: Client) => {
      setEditingId(record.id);
      setSubmitError(null);
      const fullClient = await getClient(record.id);
      if (fullClient) {
        form.setFieldsValue({
          ...fullClient,
          allowedGrantTypes: fullClient.allowedGrantTypes || [],
          authorizationPromptTypes: fullClient.authorizationPromptTypes || [],
          allowedScopes: fullClient.allowedScopes || [],
          redirectUris: fullClient.redirectUris || [],
          allowedCorsOrigins: fullClient.allowedCorsOrigins || [],
          identityProviderRestrictions: fullClient.identityProviderRestrictions || [],
          clientSecret: undefined,
        });
      }
      setModalOpen(true);
    },
    [form],
  );

  const handleSubmit = useCallback(async () => {
    try {
      const values = await form.validateFields();
      setSubmitError(null);

      const payload: CreateClientRequest | UpdateClientRequest = {
        clientName: values.clientName,
        description: values.description,
        enabled: values.enabled,
        clientType: values.clientType,
        requirePkce: values.requirePkce,
        requireClientSecret: values.clientType === 1 ? false : values.requireClientSecret,
        requireConsent: values.requireConsent,
        allowPlainTextPkce: values.allowPlainTextPkce,
        allowRememberConsent: values.allowRememberConsent,
        accessTokenLifetime: values.accessTokenLifetime,
        refreshTokenLifetime: values.refreshTokenLifetime,
        authorizationCodeLifetime: values.authorizationCodeLifetime,
        deviceCodeLifetime: values.deviceCodeLifetime,
        allowedGrantTypes: values.allowedGrantTypes || [],
        authorizationPromptTypes: values.authorizationPromptTypes || [],
        allowedScopes: values.allowedScopes || [],
        redirectUris: values.redirectUris || [],
        allowedCorsOrigins: values.allowedCorsOrigins || [],
        identityProviderRestrictions: values.identityProviderRestrictions || [],
        clientUri: values.clientUri,
        logoUri: values.logoUri,
        clientSecrets: values.clientSecret ? [{ value: values.clientSecret }] : [],
      };

      if (!editingId) {
        (payload as CreateClientRequest).clientId = values.clientId;
      }

      if (editingId) {
        await updateClient(editingId, payload);
        message.success('更新成功');
      } else {
        await createClient(payload as CreateClientRequest);
        message.success('创建成功');
      }

      setModalOpen(false);
      refresh();
    } catch (error: any) {
      const detail = error?.info?.data?.detail || error?.info?.data?.title || error?.info?.data?.errors || error?.message || '保存失败，请检查表单输入';
      setSubmitError(typeof detail === 'string' ? detail : JSON.stringify(detail));
      if (error?.errorFields == null) {
        message.error('保存失败');
      }
    }
  }, [editingId, form, refresh]);

  const handleDelete = useCallback(
    async (id: number) => {
      await deleteClient(id);
      message.success('删除成功');
      refresh();
    },
    [refresh],
  );

  const columns = [
    {
      title: '客户端',
      key: 'client',
      width: 260,
      render: (_: unknown, record: Client) => (
        <div className={styles.clientTitle}>
          <Text className={styles.clientId}>{record.clientName || record.clientId}</Text>
          <Text type="secondary" className={styles.clientMeta}>
            {record.clientId}
          </Text>
          {record.description && (
            <Text type="secondary" ellipsis={{ tooltip: record.description }}>
              {record.description}
            </Text>
          )}
        </div>
      ),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 80,
      render: (v: boolean) => (v ? <Tag color="success">启用</Tag> : <Tag color="error">禁用</Tag>),
    },
    {
      title: '客户端类型',
      dataIndex: 'clientType',
      key: 'clientType',
      width: 100,
      render: (v: number) => (v === 0 ? <Tag>机密</Tag> : <Tag color="blue">公开</Tag>),
    },
    {
      title: '授权类型',
      dataIndex: 'allowedGrantTypes',
      key: 'allowedGrantTypes',
      render: (v: string[]) => (
        <div className={styles.tagWrap}>
          {v?.map((g: string) => (
            <Tag key={g}>{g}</Tag>
          ))}
        </div>
      ),
    },
    {
      title: 'Prompt 限制',
      dataIndex: 'authorizationPromptTypes',
      key: 'authorizationPromptTypes',
      width: 180,
      render: (v?: string[]) =>
        v && v.length > 0 ? (
          <div className={styles.tagWrap}>
            {v.map((prompt) => (
              <Tag key={prompt} color="processing">
                {prompt}
              </Tag>
            ))}
          </div>
        ) : (
          <Tag>全部允许</Tag>
        ),
    },
    {
      title: 'IdP 限制',
      dataIndex: 'identityProviderRestrictions',
      key: 'identityProviderRestrictions',
      width: 180,
      render: (v?: string[]) =>
        v && v.length > 0 ? (
          <div className={styles.tagWrap}>
            {v.map((provider) => (
              <Tag key={provider} color="purple">
                {provider}
              </Tag>
            ))}
          </div>
        ) : (
          <Tag>全部允许</Tag>
        ),
    },
    {
      title: '安全态势',
      key: 'securityPosture',
      width: 200,
      render: (_: unknown, record: Client) => (
        <div className={styles.tagWrap}>
          {record.requirePkce && <Tag color="blue">PKCE</Tag>}
          {record.requireConsent && <Tag color="gold">Consent</Tag>}
          {record.requireClientSecret && <Tag color="green">Secret</Tag>}
          {!record.requireClientSecret && <Tag color="volcano">Public</Tag>}
        </div>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 120,
      render: (_: unknown, record: Client) => (
        <Space size="small">
          <a onClick={() => handleEdit(record)}>编辑</a>
          <Popconfirm title="确认删除?" onConfirm={() => handleDelete(record.id)}>
            <a style={{ color: '#ff4d4f' }}>删除</a>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <PageContainer>
      <div className={styles.summaryGrid}>
        <Card className={styles.summaryCard}>
          <Statistic title="客户端总数" value={summary.total} prefix={<SafetyCertificateOutlined />} />
        </Card>
        <Card className={styles.summaryCard}>
          <Statistic title="已启用" value={summary.enabled} valueStyle={{ color: '#1677ff' }} />
        </Card>
        <Card className={styles.summaryCard}>
          <Statistic title="机密客户端" value={summary.confidential} valueStyle={{ color: '#13a8a8' }} />
        </Card>
        <Card className={styles.summaryCard}>
          <Statistic title="需要 Consent" value={summary.requireConsent} valueStyle={{ color: '#d48806' }} />
        </Card>
      </div>

      <Card className={styles.tableCard} bordered={false}>
        <div className={styles.toolbar}>
          <div>
            <Text type="secondary">面向管理员的快速总览：先筛选，再钻取编辑。</Text>
          </div>
          <div className={styles.toolbarActions}>
            <Input
              allowClear
              prefix={<SearchOutlined />}
              placeholder="搜索 Client ID、名称、Grant、Prompt、IdP"
              style={{ width: 320, maxWidth: '100%' }}
              value={keyword}
              onChange={(event) => setKeyword(event.target.value)}
            />
            <Tooltip title="创建新的 OAuth / OIDC 客户端配置">
              <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
                新建客户端
              </Button>
            </Tooltip>
          </div>
        </div>

        <Table columns={columns} dataSource={filteredClients} loading={loading} rowKey="id" pagination={{ pageSize: 10 }} scroll={{ x: 1180 }} />
      </Card>

      <Modal title={editingId ? '编辑客户端' : '新建客户端'} open={modalOpen} onOk={handleSubmit} onCancel={() => setModalOpen(false)} width={720} destroyOnClose maskClosable={false}>
        <Form form={form} layout="vertical" size="middle">
          {submitError && <Alert type="error" showIcon message="提交失败" description={submitError} style={{ marginBottom: 16 }} />}

          {!editingId && (
            <Card title="基本信息" size="small" className={styles.modalSection}>
              <Row gutter={16}>
                <Col span={12}>
                  <Form.Item name="clientId" label="Client ID" rules={[{ required: true, message: '请输入 Client ID' }]}>
                    <Input placeholder="my-client" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="clientType" label="客户端类型">
                    <Select options={clientTypeOptions} />
                  </Form.Item>
                </Col>
              </Row>
            </Card>
          )}

          <Card title="基本信息" size="small" className={styles.modalSection}>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="clientName" label="客户端名称">
                  <Input placeholder="My Application" />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="enabled" label="启用" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
            </Row>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="clientUri" label="客户端主页 URI" rules={[{ type: 'url', warningOnly: true, message: '请输入有效 URL' }]}>
                  <Input placeholder="https://app.example.com" />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="logoUri" label="Logo URI" rules={[{ type: 'url', warningOnly: true, message: '请输入有效 URL' }]}>
                  <Input placeholder="https://app.example.com/logo.png" />
                </Form.Item>
              </Col>
            </Row>
            <Form.Item name="description" label="描述">
              <Input.TextArea rows={2} placeholder="客户端描述信息" />
            </Form.Item>
          </Card>

          <Card title="授权配置" size="small" className={styles.modalSection}>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="requirePkce" label="要求 PKCE" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="requireClientSecret" label="要求 Client Secret" valuePropName="checked">
                  <Switch disabled={watchedClientType === 1} />
                </Form.Item>
              </Col>
            </Row>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="requireConsent" label="要求用户同意" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="allowPlainTextPkce" label="允许纯文本 PKCE" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
            </Row>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="allowRememberConsent" label="允许记住同意" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
            </Row>
            <Form.Item name="allowedGrantTypes" label="授权类型" rules={[{ required: true, message: '请选择授权类型' }]}>
              <Select mode="multiple" options={grantTypeOptions} placeholder="选择授权类型" />
            </Form.Item>
            <Form.Item name="authorizationPromptTypes" label="允许的 Prompt 类型" extra="可选。配置后将限制客户端可使用的 prompt 值。">
              <Select mode="multiple" options={promptTypeOptions} placeholder="选择允许的 prompt 类型" />
            </Form.Item>
            <Form.Item name="allowedScopes" label="允许的作用域">
              <Select mode="multiple" options={scopeOptions} placeholder="选择允许的作用域" />
            </Form.Item>
            <Form.Item name="identityProviderRestrictions" label="Identity Provider 限制" extra="可选。填写后仅允许这些外部/本地身份提供方参与登录与账号选择。">
              <Select mode="tags" placeholder="例如：local、github、azuread" />
            </Form.Item>
          </Card>

          <Card title="重定向配置" size="small" className={styles.modalSection}>
            <Form.Item
              name="redirectUris"
              label="重定向 URI"
              rules={[
                {
                  validator: async (_, value: string[] | undefined) => {
                    const uris = value ?? [];
                    for (const uri of uris) {
                      try {
                        const parsed = new URL(uri);
                        if (parsed.hash) {
                          throw new Error('URI 不允许包含 fragment');
                        }
                      } catch {
                        throw new Error(`无效重定向 URI: ${uri}`);
                      }
                    }
                  },
                },
              ]}
            >
              <Select mode="tags" placeholder="输入 URI 后回车" />
            </Form.Item>
            <Form.Item
              name="allowedCorsOrigins"
              label="允许的 CORS 源"
              rules={[
                {
                  validator: async (_, value: string[] | undefined) => {
                    const origins = value ?? [];
                    for (const origin of origins) {
                      try {
                        const parsed = new URL(origin);
                        if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
                          throw new Error('CORS 源只能包含协议、主机和端口');
                        }
                      } catch {
                        throw new Error(`无效 CORS 源: ${origin}`);
                      }
                    }
                  },
                },
              ]}
            >
              <Select mode="tags" placeholder="输入跨域源后回车" />
            </Form.Item>
          </Card>

          <Card title="令牌配置" size="small" className={styles.modalSection}>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="accessTokenLifetime" label="Access Token 有效期(秒)">
                  <InputNumber min={60} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="refreshTokenLifetime" label="Refresh Token 有效期(秒)">
                  <InputNumber min={60} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
            </Row>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="authorizationCodeLifetime" label="授权码有效期(秒)">
                  <InputNumber min={60} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="deviceCodeLifetime" label="设备代码有效期(秒)">
                  <InputNumber min={60} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
            </Row>
          </Card>

          {!editingId && (
            <Card title="安全配置" size="small" className={styles.modalSection}>
              <Form.Item name="clientSecret" label="Client Secret" extra="留空则不设置 Secret" hidden={watchedClientType === 1}>
                <Input.Password placeholder="留空则不设置" />
              </Form.Item>
            </Card>
          )}

          {editingId && (
            <Card title="密钥轮换" size="small" className={styles.modalSection}>
              <Form.Item name="clientSecret" label="新的 Client Secret" extra="填写后将替换现有密钥" hidden={watchedClientType === 1}>
                <Input.Password placeholder="留空表示不变更" />
              </Form.Item>
            </Card>
          )}
        </Form>
      </Modal>
    </PageContainer>
  );
}
