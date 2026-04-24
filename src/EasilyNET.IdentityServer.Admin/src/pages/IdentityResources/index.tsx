import { useState, useCallback } from 'react';
import { PageContainer } from '@ant-design/pro-components';
import { Button, Table, Space, Modal, Form, Input, Select, Switch, Tag, message, Popconfirm, Card, Row, Col } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useRequest } from '@umijs/max';
import { getIdentityResources, getIdentityResource, createIdentityResource, updateIdentityResource, deleteIdentityResource, IdentityResource, CreateIdentityResourceRequest } from '@/services/api';

export default function IdentityResourcesPage() {
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form] = Form.useForm();

  const { data: resources, loading, refresh } = useRequest(getIdentityResources);

  const handleCreate = useCallback(() => {
    setEditingId(null);
    form.resetFields();
    form.setFieldsValue({ enabled: true, required: false, emphasize: false, showInDiscoveryDocument: true });
    setModalOpen(true);
  }, [form]);

  const handleEdit = useCallback(async (record: IdentityResource) => {
    setEditingId(record.id);
    const fullResource = await getIdentityResource(record.id);
    form.setFieldsValue({
      ...fullResource,
    });
    setModalOpen(true);
  }, [form]);

  const handleSubmit = useCallback(async () => {
    const values = await form.validateFields();
    const payload: CreateIdentityResourceRequest = {
      name: values.name,
      displayName: values.displayName,
      description: values.description,
      enabled: values.enabled,
      required: values.required,
      emphasize: values.emphasize,
      showInDiscoveryDocument: values.showInDiscoveryDocument,
      userClaims: values.userClaims || [],
    };

    if (editingId) {
      await updateIdentityResource(editingId, payload);
      message.success('更新成功');
    } else {
      await createIdentityResource(payload);
      message.success('创建成功');
    }
    setModalOpen(false);
    refresh();
  }, [editingId, form, refresh]);

  const handleDelete = useCallback(async (id: number) => {
    await deleteIdentityResource(id);
    message.success('删除成功');
    refresh();
  }, [refresh]);

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name', width: 120 },
    { title: '显示名称', dataIndex: 'displayName', key: 'displayName', width: 150, ellipsis: true },
    {
      title: '状态', dataIndex: 'enabled', key: 'enabled', width: 80,
      render: (v: boolean) => v ? <Tag color="success">启用</Tag> : <Tag color="error">禁用</Tag>,
    },
    {
      title: '必需', dataIndex: 'required', key: 'required', width: 70,
      render: (v: boolean) => v ? <Tag color="orange">是</Tag> : <Tag>否</Tag>,
    },
    {
      title: '显示', dataIndex: 'showInDiscoveryDocument', key: 'showInDiscoveryDocument', width: 80,
      render: (v: boolean) => v ? <Tag color="cyan">是</Tag> : <Tag>否</Tag>,
    },
    {
      title: 'Claims', dataIndex: 'userClaims', key: 'userClaims',
      render: (v: string[]) => v?.map((c: string) => <Tag key={c}>{c}</Tag>),
    },
    {
      title: '操作', key: 'action', width: 120,
      render: (_: unknown, record: IdentityResource) => (
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
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新建 Identity 资源</Button>
      </div>
      <Table columns={columns} dataSource={resources} loading={loading} rowKey="id" pagination={{ pageSize: 10 }} />

      <Modal
        title={editingId ? '编辑 Identity 资源' : '新建 Identity 资源'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        width={560}
        destroyOnClose
        maskClosable={false}
      >
        <Form form={form} layout="vertical" size="middle">
          {!editingId && (
            <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入 Identity 资源名称' }]}>
              <Input placeholder="openid / profile / email" />
            </Form.Item>
          )}

          <Card title="基本信息" size="small">
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="displayName" label="显示名称">
                  <Input placeholder="用户信息" />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="enabled" label="启用" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
            </Row>
            <Form.Item name="description" label="描述">
              <Input.TextArea rows={2} placeholder="Identity 资源描述" />
            </Form.Item>
          </Card>

          <Card title="权限配置" size="small" style={{ marginTop: 16 }}>
            <Row gutter={16}>
              <Col span={8}>
                <Form.Item name="required" label="必需" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
              <Col span={8}>
                <Form.Item name="emphasize" label="强调显示" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
              <Col span={8}>
                <Form.Item name="showInDiscoveryDocument" label="显示在发现文档" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Col>
            </Row>
          </Card>

          <Card title="Claims 配置" size="small" style={{ marginTop: 16 }}>
            <Form.Item name="userClaims" label="User Claims" extra="身份令牌中包含的用户声明">
              <Select mode="tags" placeholder="输入 claim 类型后回车 (如 sub, name, email)" />
            </Form.Item>
          </Card>
        </Form>
      </Modal>
    </PageContainer>
  );
}