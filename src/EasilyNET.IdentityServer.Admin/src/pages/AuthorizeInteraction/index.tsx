import { Alert, App, Avatar, Button, Card, Checkbox, Col, Divider, Empty, Input, List, Result, Row, Space, Spin, Tag, Typography } from 'antd';
import { AuthorizationRequestContextResponse, AuthorizationScopeDescriptor, getAuthorizationInteractionContext, submitAuthorizationInteraction } from '@/services/api';
import { LockOutlined, LoginOutlined, SafetyCertificateOutlined, UserSwitchOutlined } from '@ant-design/icons';
import { history, useLocation } from '@umijs/max';
import { useCallback, useEffect, useMemo, useState } from 'react';

const { Paragraph, Text, Title } = Typography;

const riskColorMap: Record<string, string> = {
  low: 'green',
  medium: 'gold',
  high: 'red',
};

const stepMeta: Record<string, { icon: React.ReactNode; title: string; subtitle: string }> = {
  login: {
    icon: <LoginOutlined />,
    title: '登录以继续授权',
    subtitle: '选择一个可用账号，或手动输入 subject 标识来继续授权流程。',
  },
  select_account: {
    icon: <UserSwitchOutlined />,
    title: '选择要继续授权的账号',
    subtitle: '当前客户端要求明确选择账号，避免把令牌发给错误身份。',
  },
  consent: {
    icon: <SafetyCertificateOutlined />,
    title: '确认授权范围',
    subtitle: '请检查权限、风险提示与资源受众后，再决定是否继续授权。',
  },
};

export default function AuthorizeInteractionPage() {
  const location = useLocation();
  const { message } = App.useApp();
  const requestId = useMemo(() => new URLSearchParams(location.search).get('requestId')?.trim() ?? '', [location.search]);

  const [context, setContext] = useState<AuthorizationRequestContextResponse>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [submittingAction, setSubmittingAction] = useState<string>();
  const [selectedSubjectId, setSelectedSubjectId] = useState<string>();
  const [manualSubjectId, setManualSubjectId] = useState('');
  const [selectedScopes, setSelectedScopes] = useState<string[]>([]);
  const [rememberConsent, setRememberConsent] = useState(false);

  const loadContext = useCallback(async () => {
    if (!requestId) {
      setError('缺少 requestId，无法加载授权交互上下文。');
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(undefined);
      const nextContext = await getAuthorizationInteractionContext(requestId);
      setContext(nextContext);
      setSelectedSubjectId(nextContext.selectedAccount?.subjectId ?? nextContext.subjectId ?? nextContext.availableAccounts[0]?.subjectId);
      setManualSubjectId(nextContext.subjectId ?? '');
      setSelectedScopes(nextContext.pendingConsentScopes.length > 0 ? nextContext.pendingConsentScopes : nextContext.requestedScopes);
      setRememberConsent(false);
    } catch (err: any) {
      const detail = err?.info?.data?.detail || err?.info?.data?.title || err?.message || '加载授权请求上下文失败';
      setError(typeof detail === 'string' ? detail : JSON.stringify(detail));
    } finally {
      setLoading(false);
    }
  }, [requestId]);

  useEffect(() => {
    void loadContext();
  }, [loadContext]);

  const scopeGroups = useMemo(() => {
    const groups = new Map<string, AuthorizationScopeDescriptor[]>();
    for (const scope of context?.requestedScopeDetails ?? []) {
      const key = scope.displayGroup || 'Other permissions';
      groups.set(key, [...(groups.get(key) ?? []), scope]);
    }

    return Array.from(groups.entries());
  }, [context?.requestedScopeDetails]);

  const currentStep = context?.interactionType ?? 'login';
  const stepInfo = stepMeta[currentStep] ?? stepMeta.login;

  const resolvedSubjectId = useMemo(() => {
    const accountBased = selectedSubjectId?.trim();
    if (accountBased) {
      return accountBased;
    }

    const manual = manualSubjectId.trim();
    return manual || undefined;
  }, [manualSubjectId, selectedSubjectId]);

  const canSubmitPrimary = useMemo(() => {
    if (!context) {
      return false;
    }

    if (currentStep === 'consent') {
      return selectedScopes.length > 0;
    }

    return Boolean(resolvedSubjectId);
  }, [context, currentStep, resolvedSubjectId, selectedScopes.length]);

  const handleAction = useCallback(
    async (action: 'login' | 'select_account' | 'consent' | 'deny') => {
      if (!context) {
        return;
      }

      try {
        setSubmittingAction(action);
        setError(undefined);
        const result = await submitAuthorizationInteraction({
          requestId: context.requestId,
          action,
          consentGranted: action === 'deny' ? false : true,
          rememberConsent: action === 'consent' ? rememberConsent : false,
          scopes: action === 'consent' ? selectedScopes : undefined,
          subjectId: action === 'deny' ? undefined : resolvedSubjectId,
        });

        if (result.outcome === 'redirect' && result.redirectUrl) {
          window.location.assign(result.redirectUrl);
          return;
        }

        if (result.outcome === 'interaction_required') {
          await loadContext();
          message.info('授权步骤已更新，请继续完成后续操作。');
          return;
        }

        setError('交互响应未返回可继续的结果。');
      } catch (err: any) {
        const detail = err?.info?.data?.detail || err?.info?.data?.title || err?.message || '提交授权交互失败';
        setError(typeof detail === 'string' ? detail : JSON.stringify(detail));
      } finally {
        setSubmittingAction(undefined);
      }
    },
    [context, loadContext, message, rememberConsent, resolvedSubjectId, selectedScopes],
  );

  const handleScopeToggle = useCallback((scope: AuthorizationScopeDescriptor, checked: boolean) => {
    if (!scope.isSelectable) {
      return;
    }

    setSelectedScopes((current) => {
      if (checked) {
        return current.includes(scope.name) ? current : [...current, scope.name];
      }

      return current.filter((item) => item !== scope.name);
    });
  }, []);

  const primaryActionLabel = currentStep === 'consent' ? '确认并继续授权' : currentStep === 'select_account' ? '使用所选账号继续' : '登录并继续';
  const primaryAction = currentStep === 'consent' ? 'consent' : currentStep === 'select_account' ? 'select_account' : 'login';

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: '#f5f7fb' }}>
        <Space direction="vertical" size="middle" align="center">
          <Spin size="large" />
          <Text type="secondary">正在加载授权交互上下文…</Text>
        </Space>
      </div>
    );
  }

  if (!requestId) {
    return (
      <Result
        status="warning"
        title="缺少授权请求标识"
        subTitle="请从授权端点返回的 interaction 响应中携带 requestId 打开该页面。"
        extra={
          <Button type="primary" onClick={() => history.push('/clients')}>
            返回管理后台
          </Button>
        }
      />
    );
  }

  if (!context) {
    return (
      <Result
        status="error"
        title="无法加载授权上下文"
        subTitle={error || '授权请求上下文不存在、已过期，或当前网关无法访问 IdentityServer。'}
        extra={
          <Button type="primary" onClick={() => void loadContext()}>
            重试
          </Button>
        }
      />
    );
  }

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(180deg, #f7f9fc 0%, #eef3fb 100%)', padding: '40px 16px' }}>
      <Row justify="center">
        <Col xs={24} sm={22} md={20} lg={18} xl={16} xxl={14}>
          <Space direction="vertical" size={20} style={{ width: '100%' }}>
            <Card bordered={false} style={{ borderRadius: 20, boxShadow: '0 18px 50px rgba(15, 23, 42, 0.08)' }}>
              <Space size={16} align="start">
                <Avatar size={56} icon={stepInfo.icon} style={{ backgroundColor: '#1677ff' }} />
                <div style={{ flex: 1 }}>
                  <Title level={3} style={{ margin: 0 }}>
                    {stepInfo.title}
                  </Title>
                  <Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 12 }}>
                    {stepInfo.subtitle}
                  </Paragraph>
                  <Space wrap>
                    <Tag color="blue">Client ID: {context.clientId}</Tag>
                    {context.clientName && <Tag color="geekblue">{context.clientName}</Tag>}
                    <Tag color="purple">requestId: {context.requestId}</Tag>
                    {context.prompt && <Tag>prompt: {context.prompt}</Tag>}
                  </Space>
                </div>
              </Space>
            </Card>

            {error && <Alert type="error" showIcon message="操作失败" description={error} />}

            <Card title="授权上下文" bordered={false} style={{ borderRadius: 20 }}>
              <Row gutter={[16, 16]}>
                <Col xs={24} md={12}>
                  <Text type="secondary">回调地址</Text>
                  <Paragraph copyable style={{ marginBottom: 0 }}>
                    {context.redirectUri}
                  </Paragraph>
                </Col>
                <Col xs={24} md={12}>
                  <Text type="secondary">登录提示</Text>
                  <Paragraph style={{ marginBottom: 0 }}>{context.loginHint || '未提供'}</Paragraph>
                </Col>
                <Col xs={24} md={12}>
                  <Text type="secondary">当前步骤</Text>
                  <Paragraph style={{ marginBottom: 0 }}>{context.interactionType}</Paragraph>
                </Col>
                <Col xs={24} md={12}>
                  <Text type="secondary">允许动作</Text>
                  <Paragraph style={{ marginBottom: 0 }}>{context.availableActions.join(' / ')}</Paragraph>
                </Col>
              </Row>
            </Card>

            {(currentStep === 'login' || currentStep === 'select_account') && (
              <Card
                title={currentStep === 'select_account' ? '选择账号' : '登录账号'}
                extra={context.selectedAccount ? <Tag color="success">当前账号：{context.selectedAccount.displayName || context.selectedAccount.subjectId}</Tag> : null}
                bordered={false}
                style={{ borderRadius: 20 }}
              >
                {context.availableAccounts.length > 0 ? (
                  <List
                    itemLayout="horizontal"
                    dataSource={context.availableAccounts}
                    renderItem={(account) => {
                      const active = (selectedSubjectId || context.selectedAccount?.subjectId) === account.subjectId;
                      return (
                        <List.Item
                          onClick={() => setSelectedSubjectId(account.subjectId)}
                          style={{
                            cursor: 'pointer',
                            padding: 16,
                            borderRadius: 16,
                            marginBottom: 12,
                            border: active ? '1px solid #1677ff' : '1px solid #f0f0f0',
                            background: active ? '#f0f7ff' : '#fff',
                          }}
                        >
                          <List.Item.Meta
                            avatar={<Avatar icon={<LockOutlined />} />}
                            title={
                              <Space>
                                <Text strong>{account.displayName || account.subjectId}</Text>
                                {account.isCurrent && <Tag color="success">当前</Tag>}
                              </Space>
                            }
                            description={
                              <Space wrap>
                                <Text type="secondary">subject: {account.subjectId}</Text>
                                {account.loginHint && <Tag>{account.loginHint}</Tag>}
                                {account.identityProvider && <Tag color="purple">{account.identityProvider}</Tag>}
                              </Space>
                            }
                          />
                        </List.Item>
                      );
                    }}
                  />
                ) : (
                  <Empty description="当前没有可供选择的预置账号，请手动输入 subjectId。" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                )}

                <Divider plain>手动输入 subjectId</Divider>
                <Input
                  size="large"
                  placeholder="例如：alice"
                  value={manualSubjectId}
                  onChange={(event) => {
                    setManualSubjectId(event.target.value);
                    setSelectedSubjectId(undefined);
                  }}
                />
              </Card>
            )}

            {currentStep === 'consent' && (
              <Card
                title="确认权限与风险"
                extra={context.selectedAccount ? <Tag color="processing">授权账号：{context.selectedAccount.displayName || context.selectedAccount.subjectId}</Tag> : null}
                bordered={false}
                style={{ borderRadius: 20 }}
              >
                <Space direction="vertical" size={20} style={{ width: '100%' }}>
                  {scopeGroups.map(([group, scopes]) => (
                    <Card key={group} type="inner" title={group}>
                      <Space direction="vertical" size={16} style={{ width: '100%' }}>
                        {scopes.map((scope) => {
                          const checked = selectedScopes.includes(scope.name);
                          return (
                            <div key={scope.name} style={{ border: '1px solid #f0f0f0', borderRadius: 16, padding: 16 }}>
                              <Row gutter={[16, 12]} align="top">
                                <Col flex="32px">
                                  <Checkbox checked={checked} disabled={!scope.isSelectable} onChange={(event) => handleScopeToggle(scope, event.target.checked)} />
                                </Col>
                                <Col flex="auto">
                                  <Space wrap style={{ marginBottom: 8 }}>
                                    <Text strong>{scope.displayName || scope.name}</Text>
                                    <Tag color={riskColorMap[scope.riskLevel] ?? 'default'}>{scope.riskLevel.toUpperCase()}</Tag>
                                    <Tag>{scope.type}</Tag>
                                    {scope.required && <Tag color="orange">必选</Tag>}
                                    {scope.emphasize && <Tag color="magenta">重点</Tag>}
                                  </Space>
                                  <Paragraph style={{ marginBottom: 8 }}>{scope.consentDescription || scope.description || '该权限允许客户端代表你访问受保护资源。'}</Paragraph>
                                  {scope.selectionLockedReason && <Alert type="info" showIcon style={{ marginBottom: 12 }} message={scope.selectionLockedReason} />}
                                  {scope.consentWarnings.length > 0 && (
                                    <Alert
                                      type={scope.riskLevel === 'high' ? 'warning' : 'info'}
                                      showIcon
                                      style={{ marginBottom: 12 }}
                                      message="授权提醒"
                                      description={
                                        <ul style={{ paddingInlineStart: 18, margin: 0 }}>
                                          {scope.consentWarnings.map((warning) => (
                                            <li key={warning}>{warning}</li>
                                          ))}
                                        </ul>
                                      }
                                    />
                                  )}
                                  {scope.userClaims.length > 0 && (
                                    <div style={{ marginBottom: 8 }}>
                                      <Text type="secondary">Claims：</Text>
                                      <Space wrap>
                                        {scope.userClaims.map((claim) => (
                                          <Tag key={claim}>{claim}</Tag>
                                        ))}
                                      </Space>
                                    </div>
                                  )}
                                  {scope.resources.length > 0 && (
                                    <div>
                                      <Text type="secondary">关联资源：</Text>
                                      <Space wrap>
                                        {scope.resources.map((resource) => (
                                          <Tag key={resource.name} color="blue">
                                            {resource.displayName || resource.name}
                                          </Tag>
                                        ))}
                                      </Space>
                                    </div>
                                  )}
                                </Col>
                              </Row>
                            </div>
                          );
                        })}
                      </Space>
                    </Card>
                  ))}

                  {context.rememberConsentAllowed && (
                    <Checkbox checked={rememberConsent} onChange={(event) => setRememberConsent(event.target.checked)}>
                      记住本次同意，后续同一客户端同一权限组合可减少重复确认
                    </Checkbox>
                  )}
                </Space>
              </Card>
            )}

            <Card bordered={false} style={{ borderRadius: 20 }}>
              <Row justify="space-between" align="middle" gutter={[12, 12]}>
                <Col>
                  <Space wrap>
                    <Button onClick={() => void loadContext()}>刷新上下文</Button>
                    <Button danger onClick={() => void handleAction('deny')} loading={submittingAction === 'deny'}>
                      拒绝授权
                    </Button>
                  </Space>
                </Col>
                <Col>
                  <Button
                    type="primary"
                    size="large"
                    loading={submittingAction === primaryAction}
                    disabled={!canSubmitPrimary}
                    onClick={() => void handleAction(primaryAction as 'login' | 'select_account' | 'consent')}
                  >
                    {primaryActionLabel}
                  </Button>
                </Col>
              </Row>
            </Card>
          </Space>
        </Col>
      </Row>
    </div>
  );
}
