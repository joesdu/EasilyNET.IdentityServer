import { useState, useCallback } from 'react';
import { PageContainer } from '@ant-design/pro-components';
import { Button, Table, Space, Modal, Form, Input, Select, Switch, Tag, message, Popconfirm, Card, Row, Col } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useRequest } from '@umijs/max';
import { getApiResources, getApiResource, createApiResource, updateApiResource, deleteApiResource, ApiResource, CreateApiResourceRequest } from '@/services/api';

export default function ApiResourcesPage() {
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form] = Form.useForm();

  const { data: resources, loading, refresh } = useRequest(getApiResources);

  const handleCreate = useCallback(() => {
    setEditingId(null);
    form.resetFields();
    form.setFieldsValue({ enabled: true });
    setModalOpen(true);
  }, [form]);

  const handleEdit = useCallback(async (record: ApiResource) => {
    setEditingId(record.id);
    const fullResource = await getApiResource(record.id);
    form.setFieldsValue({
      ...fullResource,
    });
    setModalOpen(true);
  }, [form]);

  const handleSubmit = useCallback(async () => {
    const values = await form.validateFields();
    const payload: CreateApiResourceRequest = {
      name: values.name,
      displayName: values.displayName,
      description: values.description,
      enabled: values.enabled,
      scopes: values.scopes || [],
      userClaims: values.userClaims || [],
    };

    if (editingId) {
      await updateApiResource(editingId, payload);
      message.success('更新成功');
    } else {
      await createApiResource(payload);
      message.success('创建成功');
    }
    setModalOpen(false);
    refresh();
  }, [editingId, form, refresh]);

  const handleDelete = useCallback(async (id: number) => {
    await deleteApiResource(id);
    message.success('删除成功');
    refresh();
  }, [refresh]);

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name', width: 150 },
    { title: '显示名称', dataIndex: 'displayName', key: 'displayName', width: 150, ellipsis: true },
    {
      title: '状态', dataIndex: 'enabled', key: 'enabled', width: 80,
      render: (v: boolean) => v ? <Tag color="success">启用</Tag> : <Tag color="error">禁用</Tag>,
    },
    {
      title: '作用域', dataIndex: 'scopes', key: 'scopes',
      render: (v: string[]) => v?.map((s: string) => <Tag key={s} color="blue">{s}</Tag>),
    },
    {
      title: 'Claims', dataIndex: 'userClaims', key: 'userClaims',
      render: (v: string[]) => v?.map((c: string) => <Tag>{c}</Tag>),
    },
    {
      title: '操作', key: 'action', width: 120,
      render: (_: unknown, record: ApiResource) => (
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
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新建 API 资源</Button>
      </div>
      <Table columns={columns} dataSource={resources} loading={loading} rowKey="id" pagination={{ pageSize: 10 }} />

      <Modal
        title={editingId ? '编辑 API 资源' : '新建 API 资源'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        width={600}
        destroyOnClose
        maskClosable={false}
      >
        <Form form={form} layout="vertical" size="middle">
          {!editingId && (
            <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入 API 资源名称' }]}>
              <Input placeholder="my-api" />
            </Form.Item>
          )}

          <Card title="基本信息" size="small">
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="displayName" label="显示名称">
                  <Input placeholder="My API" />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="enabled" label="启用" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
            </Row>
            <Form.Item name="description" label="描述">
              <Input.TextArea rows={2} placeholder="API 资源描述" />
            </Form.Item>
          </Card>

          <Card title="作用域配置" size="small" style={{ marginTop: 16 }}>
            <Form.Item name="scopes" label="作用域" extra="定义 API 可访问的作用域">
              <Select mode="tags" placeholder="输入作用域名称后回车" />
            </Form.Item>
          </Card>

          <Card title="Claims 配置" size="small" style={{ marginTop: 16 }}>
            <Form.Item name="userClaims" label="User Claims" extra="访问令牌中包含的用户声明">
              <Select mode="tags" placeholder="输入 claim 类型后回车 (如 sub, name, email)" />
            </Form.Item>
          </Card>
        </Form>
      </Modal>
    </PageContainer>
  );
}