import { useState, useCallback } from 'react';
import { PageContainer } from '@ant-design/pro-components';
import {
  Button, Table, Space, Modal, Form, Input, Select, Switch, InputNumber, Tag, message, Popconfirm, Divider, Card, Row, Col
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useRequest } from '@umijs/max';
import { getClients, createClient, updateClient, deleteClient, Client, CreateClientRequest, UpdateClientRequest } from '@/services/api';

const grantTypeOptions = [
  { label: 'Authorization Code', value: 'authorization_code' },
  { label: 'Client Credentials', value: 'client_credentials' },
  { label: 'Refresh Token', value: 'refresh_token' },
  { label: 'Device Code', value: 'device_code' },
];

const clientTypeOptions = [
  { label: '机密客户端', value: 0 },
  { label: '公开客户端', value: 1 },
];

export default function ClientsPage() {
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form] = Form.useForm();

  const { data: clients, loading, refresh } = useRequest(getClients);

  const handleCreate = useCallback(() => {
    setEditingId(null);
    form.resetFields();
    form.setFieldsValue({
      enabled: true,
      requirePkce: true,
      requireClientSecret: true,
      accessTokenLifetime: 3600,
      refreshTokenLifetime: 86400,
      authorizationCodeLifetime: 300,
      deviceCodeLifetime: 300,
      clientType: 0,
    });
    setModalOpen(true);
  }, [form]);

  const handleEdit = useCallback(async (record: Client) => {
    setEditingId(record.id);
    // Fetch full client details for editing
    const fullClient = await getClients().then(clients => clients.find(c => c.id === record.id));
    if (fullClient) {
      form.setFieldsValue({
        ...fullClient,
        allowedGrantTypes: fullClient.allowedGrantTypes || [],
        allowedScopes: fullClient.allowedScopes || [],
        redirectUris: fullClient.redirectUris || [],
        allowedCorsOrigins: fullClient.allowedCorsOrigins || [],
      });
    }
    setModalOpen(true);
  }, [form]);

  const handleSubmit = useCallback(async () => {
    const values = await form.validateFields();
    const payload: CreateClientRequest | UpdateClientRequest = {
      clientName: values.clientName,
      description: values.description,
      enabled: values.enabled,
      clientType: values.clientType,
      requirePkce: values.requirePkce,
      requireClientSecret: values.requireClientSecret,
      requireConsent: values.requireConsent,
      accessTokenLifetime: values.accessTokenLifetime,
      refreshTokenLifetime: values.refreshTokenLifetime,
      authorizationCodeLifetime: values.authorizationCodeLifetime,
      deviceCodeLifetime: values.deviceCodeLifetime,
      allowPlainTextPkce: values.allowPlainTextPkce,
      allowRememberConsent: values.allowRememberConsent,
      allowedGrantTypes: values.allowedGrantTypes || [],
      allowedScopes: values.allowedScopes || [],
      redirectUris: values.redirectUris || [],
      allowedCorsOrigins: values.allowedCorsOrigins || [],
      clientSecrets: values.clientSecret ? [{ value: values.clientSecret }] : [],
    };

    if (!editingId) {
      (payload as CreateClientRequest).clientId = values.clientId;
    }

    if (editingId) {
      await updateClient(editingId, payload);
      message.success('更新成功');
    } else {
      await createClient(payload);
      message.success('创建成功');
    }
    setModalOpen(false);
    refresh();
  }, [editingId, form, refresh]);

  const handleDelete = useCallback(async (id: number) => {
    await deleteClient(id);
    message.success('删除成功');
    refresh();
  }, [refresh]);

  const columns = [
    { title: 'Client ID', dataIndex: 'clientId', key: 'clientId', width: 150, ellipsis: true },
    { title: '名称', dataIndex: 'clientName', key: 'clientName', width: 120, ellipsis: true },
    {
      title: '状态', dataIndex: 'enabled', key: 'enabled', width: 80,
      render: (v: boolean) => v ? <Tag color="success">启用</Tag> : <Tag color="error">禁用</Tag>,
    },
    {
      title: '客户端类型', dataIndex: 'clientType', key: 'clientType', width: 100,
      render: (v: number) => v === 0 ? <Tag>机密</Tag> : <Tag color="blue">公开</Tag>,
    },
    {
      title: '授权类型', dataIndex: 'allowedGrantTypes', key: 'allowedGrantTypes',
      render: (v: string[]) => v?.map((g: string) => <Tag key={g}>{g}</Tag>),
    },
    {
      title: '操作', key: 'action', width: 120,
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
      <div style={{ marginBottom: 16 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新建客户端</Button>
      </div>
      <Table columns={columns} dataSource={clients} loading={loading} rowKey="id" pagination={{ pageSize: 10 }} />

      <Modal
        title={editingId ? '编辑客户端' : '新建客户端'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        width={720}
        destroyOnClose
        maskClosable={false}
      >
        <Form form={form} layout="vertical" size="middle">
          {!editingId && (
            <Card title="基本信息" size="small">
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

          <Card title="基本信息" size="small" style={{ marginTop: 16 }}>
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
            <Form.Item name="description" label="描述">
              <Input.TextArea rows={2} placeholder="客户端描述信息" />
            </Form.Item>
          </Card>

          <Card title="授权配置" size="small" style={{ marginTop: 16 }}>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="requirePkce" label="要求 PKCE" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="requireClientSecret" label="要求 Client Secret" valuePropName="checked">
                  <Switch />
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
            <Form.Item name="allowedGrantTypes" label="授权类型" rules={[{ required: true, message: '请选择授权类型' }]}>
              <Select mode="multiple" options={grantTypeOptions} placeholder="选择授权类型" />
            </Form.Item>
            <Form.Item name="allowedScopes" label="允许的作用域">
              <Select mode="tags" placeholder="输入作用域名称后回车" />
            </Form.Item>
          </Card>

          <Card title="重定向配置" size="small" style={{ marginTop: 16 }}>
            <Form.Item name="redirectUris" label="重定向 URI">
              <Select mode="tags" placeholder="输入 URI 后回车" />
            </Form.Item>
            <Form.Item name="allowedCorsOrigins" label="允许的 CORS 源">
              <Select mode="tags" placeholder="输入跨域源后回车" />
            </Form.Item>
          </Card>

          <Card title="令牌配置" size="small" style={{ marginTop: 16 }}>
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
            <Card title="安全配置" size="small" style={{ marginTop: 16 }}>
              <Form.Item name="clientSecret" label="Client Secret" extra="留空则不设置 Secret">
                <Input.Password placeholder="留空则不设置" />
              </Form.Item>
            </Card>
          )}
        </Form>
      </Modal>
    </PageContainer>
  );
}