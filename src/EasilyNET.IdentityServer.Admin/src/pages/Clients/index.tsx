import { useState, useCallback } from 'react';
import { PageContainer } from '@ant-design/pro-components';
import { Button, Table, Space, Modal, Form, Input, Select, Switch, InputNumber, Tag, message, Popconfirm } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useRequest } from '@umijs/max';
import { getClients, createClient, updateClient, deleteClient } from '@/services/api';

const grantTypeOptions = [
  { label: 'Authorization Code', value: 'authorization_code' },
  { label: 'Client Credentials', value: 'client_credentials' },
  { label: 'Refresh Token', value: 'refresh_token' },
  { label: 'Device Code', value: 'device_code' },
];

export default function ClientsPage() {
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form] = Form.useForm();

  const { data: clients, loading, refresh } = useRequest(getClients);

  const handleCreate = useCallback(() => {
    setEditingId(null);
    form.resetFields();
    form.setFieldsValue({ enabled: true, requirePkce: true, requireClientSecret: true, accessTokenLifetime: 3600, refreshTokenLifetime: 86400 });
    setModalOpen(true);
  }, [form]);

  const handleEdit = useCallback((record: any) => {
    setEditingId(record.id);
    form.setFieldsValue({
      ...record,
      allowedGrantTypes: record.allowedGrantTypes || [],
      allowedScopes: record.allowedScopes || [],
      redirectUris: record.redirectUris || [],
    });
    setModalOpen(true);
  }, [form]);

  const handleSubmit = useCallback(async () => {
    const values = await form.validateFields();
    const payload = {
      ...values,
      clientType: values.requireClientSecret ? 0 : 1,
      clientSecrets: values.clientSecret ? [{ value: values.clientSecret }] : [],
    };
    delete payload.clientSecret;

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
    { title: 'Client ID', dataIndex: 'clientId', key: 'clientId' },
    { title: '名称', dataIndex: 'clientName', key: 'clientName' },
    {
      title: '状态', dataIndex: 'enabled', key: 'enabled',
      render: (v: boolean) => v ? <Tag color="green">启用</Tag> : <Tag color="red">禁用</Tag>,
    },
    {
      title: '授权类型', dataIndex: 'allowedGrantTypes', key: 'allowedGrantTypes',
      render: (v: string[]) => v?.map((g: string) => <Tag key={g}>{g}</Tag>),
    },
    {
      title: '作用域', dataIndex: 'allowedScopes', key: 'allowedScopes',
      render: (v: string[]) => v?.map((s: string) => <Tag key={s} color="blue">{s}</Tag>),
    },
    {
      title: '操作', key: 'action',
      render: (_: any, record: any) => (
        <Space>
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
      <Table columns={columns} dataSource={clients} loading={loading} rowKey="id" />

      <Modal
        title={editingId ? '编辑客户端' : '新建客户端'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        width={640}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          {!editingId && (
            <Form.Item name="clientId" label="Client ID" rules={[{ required: true }]}>
              <Input placeholder="my-client" />
            </Form.Item>
          )}
          <Form.Item name="clientName" label="客户端名称">
            <Input />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} />
          </Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="allowedGrantTypes" label="授权类型" rules={[{ required: true }]}>
            <Select mode="multiple" options={grantTypeOptions} />
          </Form.Item>
          <Form.Item name="allowedScopes" label="允许的作用域">
            <Select mode="tags" placeholder="输入作用域名称后回车" />
          </Form.Item>
          <Form.Item name="redirectUris" label="重定向 URI">
            <Select mode="tags" placeholder="输入 URI 后回车" />
          </Form.Item>
          <Form.Item name="requirePkce" label="要求 PKCE" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="requireClientSecret" label="要求 Client Secret" valuePropName="checked">
            <Switch />
          </Form.Item>
          {!editingId && (
            <Form.Item name="clientSecret" label="Client Secret">
              <Input.Password placeholder="留空则不设置" />
            </Form.Item>
          )}
          <Form.Item name="requireConsent" label="要求用户同意" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Space>
            <Form.Item name="accessTokenLifetime" label="Access Token 有效期(秒)">
              <InputNumber min={60} />
            </Form.Item>
            <Form.Item name="refreshTokenLifetime" label="Refresh Token 有效期(秒)">
              <InputNumber min={60} />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </PageContainer>
  );
}
