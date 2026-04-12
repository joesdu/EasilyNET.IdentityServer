import { useState, useCallback } from 'react';
import { PageContainer } from '@ant-design/pro-components';
import { Button, Table, Space, Modal, Form, Input, Select, Switch, Tag, message, Popconfirm } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useRequest } from '@umijs/max';
import { getApiScopes, createApiScope, deleteApiScope } from '@/services/api';

export default function ApiScopesPage() {
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm();

  const { data: scopes, loading, refresh } = useRequest(getApiScopes);

  const handleCreate = useCallback(() => {
    form.resetFields();
    form.setFieldsValue({ enabled: true, required: false, emphasize: false });
    setModalOpen(true);
  }, [form]);

  const handleSubmit = useCallback(async () => {
    const values = await form.validateFields();
    await createApiScope(values);
    message.success('创建成功');
    setModalOpen(false);
    refresh();
  }, [form, refresh]);

  const handleDelete = useCallback(async (id: number) => {
    await deleteApiScope(id);
    message.success('删除成功');
    refresh();
  }, [refresh]);

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '显示名称', dataIndex: 'displayName', key: 'displayName' },
    { title: '描述', dataIndex: 'description', key: 'description' },
    {
      title: '状态', dataIndex: 'enabled', key: 'enabled',
      render: (v: boolean) => v ? <Tag color="green">启用</Tag> : <Tag color="red">禁用</Tag>,
    },
    {
      title: '必需', dataIndex: 'required', key: 'required',
      render: (v: boolean) => v ? <Tag color="orange">是</Tag> : <Tag>否</Tag>,
    },
    {
      title: 'Claims', dataIndex: 'userClaims', key: 'userClaims',
      render: (v: string[]) => v?.map((c: string) => <Tag key={c}>{c}</Tag>),
    },
    {
      title: '操作', key: 'action',
      render: (_: any, record: any) => (
        <Space>
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
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新建 API 作用域</Button>
      </div>
      <Table columns={columns} dataSource={scopes} loading={loading} rowKey="id" />

      <Modal
        title="新建 API 作用域"
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        width={560}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label="名称" rules={[{ required: true }]}>
            <Input placeholder="read:orders" />
          </Form.Item>
          <Form.Item name="displayName" label="显示名称">
            <Input />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} />
          </Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="required" label="必需" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="emphasize" label="强调显示" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="userClaims" label="User Claims">
            <Select mode="tags" placeholder="输入 claim 类型后回车" />
          </Form.Item>
        </Form>
      </Modal>
    </PageContainer>
  );
}
