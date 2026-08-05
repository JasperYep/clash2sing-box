#!/usr/bin/env ruby
# frozen_string_literal: true

require 'base64'
require 'fileutils'
require 'json'
require 'net/http'
require 'openssl'
require 'optparse'
require 'pathname'
require 'set'
require 'stringio'
require 'uri'
require 'yaml'
require 'zlib'

class Fetcher
  DEFAULT_HEADERS = {
    'User-Agent' => 'clash-verge/v2 sing-box-config-converter/1.0',
    'Accept' => '*/*',
    'Accept-Encoding' => 'identity'
  }.freeze

  def initialize(extra_headers = {})
    @headers = DEFAULT_HEADERS.merge(extra_headers)
  end

  def fetch(url, limit = 5)
    raise "redirect limit exceeded while fetching #{url}" if limit.negative?

    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.open_timeout = 20
    http.read_timeout = 60

    request = Net::HTTP::Get.new(uri)
    @headers.each { |key, value| request[key] = value }
    response = http.request(request)

    case response
    when Net::HTTPSuccess
      decode_body(response)
    when Net::HTTPRedirection
      location = response['location']
      raise "redirect without location while fetching #{url}" if location.to_s.empty?

      fetch(URI.join(url, location).to_s, limit - 1)
    else
      raise "HTTP #{response.code} #{response.message} while fetching #{url}"
    end
  end

  private

  def decode_body(response)
    body = response.body.to_s
    return body unless response['content-encoding'].to_s.downcase.include?('gzip')

    Zlib::GzipReader.new(StringIO.new(body)).read
  rescue Zlib::GzipFile::Error
    body
  end
end

class ClashToSingBox
  GEOIP_BASE = 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set'.freeze
  GEOSITE_BASE = 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set'.freeze
  RESERVED_OUTBOUND_NAMES = %w[DIRECT REJECT REJECT-DROP GLOBAL].freeze

  attr_reader :warnings

  def initialize(document, options)
    @document = document || {}
    @options = options
    @warnings = []
    @seen_tags = Set.new(%w[direct block mixed-in tun-in local-dns remote-dns])
    @proxy_name_to_tag = {}
    @group_name_to_tag = {}
    @proxy_outbounds = []
    @group_outbounds = []
    @rule_sets = {}
    @provider_proxy_names = {}
  end

  def convert
    load_proxy_providers!
    convert_proxies!
    convert_proxy_groups!
    ensure_default_groups! if @group_outbounds.empty?

    translated_rules, explicit_final = convert_rules
    final_tag = explicit_final || infer_final_tag
    proxy_detour = infer_proxy_detour(final_tag)

    attach_rule_set_download_detours!(proxy_detour)

    config = {
      'log' => {
        'level' => 'info',
        'timestamp' => true
      },
      'dns' => build_dns(proxy_detour),
      'inbounds' => build_inbounds,
      'outbounds' => build_outbounds,
      'route' => build_route(translated_rules, final_tag),
      'experimental' => build_experimental
    }

    prune(config)
  end

  private

  def load_proxy_providers!
    providers = @document['proxy-providers'] || @document['proxy_providers'] || {}
    providers.each do |provider_name, provider|
      @provider_proxy_names[provider_name.to_s] = load_provider_proxy_names(provider_name.to_s, provider || {})
    end
  end

  def load_provider_proxy_names(provider_name, provider)
    @document['proxies'] ||= []
    text =
      if provider['url']
        @options[:fetcher].fetch(provider['url'])
      elsif provider['path']
        path = provider['path']
        full_path = if Pathname.new(path).absolute?
                      path
                    else
                      File.expand_path(path, @options[:source_dir] || Dir.pwd)
                    end
        File.read(full_path)
      else
        @warnings << "跳过 proxy-provider #{provider_name}：既没有 url 也没有 path。"
        return []
      end

    parsed = parse_document(text)
    proxies = Array(parsed['proxies'])
    proxies.each do |proxy|
      @document['proxies'] << proxy
    end
    proxies.map { |proxy| proxy['name'].to_s }.reject(&:empty?)
  rescue StandardError => e
    @warnings << "加载 proxy-provider #{provider_name} 失败：#{e.message}"
    []
  end

  def convert_proxies!
    Array(@document['proxies']).each do |proxy|
      name = proxy['name'].to_s
      if name.empty?
        @warnings << '跳过一个没有 name 的代理节点。'
        next
      end

      if RESERVED_OUTBOUND_NAMES.include?(name.upcase)
        @warnings << "节点 #{name} 与 Clash 保留关键字冲突，已跳过。"
        next
      end

      if @proxy_name_to_tag.key?(name)
        @warnings << "节点 #{name} 重名，Clash 分组无法区分，已跳过重复项。"
        next
      end

      outbound = convert_proxy(proxy)
      next unless outbound

      tag = unique_tag(name)
      outbound['tag'] = tag
      @proxy_name_to_tag[name] = tag
      @proxy_outbounds << prune(outbound)
    end

    raise '没有找到可转换的 Clash 节点。' if @proxy_outbounds.empty?
  end

  def convert_proxy(proxy)
    type = proxy['type'].to_s.downcase

    case type
    when 'ss'
      convert_shadowsocks(proxy)
    when 'trojan'
      convert_trojan(proxy)
    when 'vmess'
      convert_vmess(proxy)
    when 'vless'
      convert_vless(proxy)
    when 'hysteria2', 'hy2'
      convert_hysteria2(proxy)
    when 'hysteria'
      convert_hysteria(proxy)
    when 'tuic'
      convert_tuic(proxy)
    when 'socks5', 'socks'
      convert_socks(proxy)
    when 'http'
      convert_http(proxy)
    else
      @warnings << "节点 #{proxy['name']} 的类型 #{type.inspect} 暂不支持，已跳过。"
      nil
    end
  rescue StandardError => e
    @warnings << "节点 #{proxy['name']} 转换失败：#{e.message}"
    nil
  end

  def convert_proxy_groups!
    groups = Array(@document['proxy-groups'] || @document['proxy_groups'])
    groups.each do |group|
      name = group['name'].to_s
      next if name.empty?

      if @group_name_to_tag.key?(name)
        @warnings << "代理组 #{name} 重名，已跳过重复项。"
        next
      end

      @group_name_to_tag[name] = unique_tag(name)
    end

    groups.each do |group|
      name = group['name'].to_s
      next if name.empty?

      tag = @group_name_to_tag[name]
      next unless tag

      members = expand_group_members(group)
      if members.empty?
        @warnings << "代理组 #{name} 展开后为空，已跳过。"
        next
      end

      outbound = group_outbound(group, tag, members)
      @group_outbounds << prune(outbound) if outbound
    end
  end

  def group_outbound(group, tag, members)
    type = group['type'].to_s.downcase
    common = {
      'tag' => tag,
      'outbounds' => members
    }

    case type
    when 'select'
      common.merge(
        'type' => 'selector',
        'default' => members.first,
        'interrupt_exist_connections' => true
      )
    when 'url-test', 'urltest'
      common.merge(
        'type' => 'urltest',
        'url' => group['url'] || 'https://www.gstatic.com/generate_204',
        'interval' => duration(group['interval']) || '3m',
        'tolerance' => integer_or_nil(group['tolerance']) || 50,
        'interrupt_exist_connections' => true
      )
    when 'fallback', 'load-balance'
      @warnings << "代理组 #{group['name']} 的类型 #{type} 在 sing-box 中没有等价实现，已近似转换为 urltest。"
      common.merge(
        'type' => 'urltest',
        'url' => group['url'] || 'https://www.gstatic.com/generate_204',
        'interval' => duration(group['interval']) || '3m',
        'tolerance' => integer_or_nil(group['tolerance']) || 50,
        'interrupt_exist_connections' => true
      )
    when 'relay'
      @warnings << "代理组 #{group['name']} 的 relay 链式转发没有直接等价实现，已近似转换为 selector。"
      common.merge(
        'type' => 'selector',
        'default' => members.first,
        'interrupt_exist_connections' => true
      )
    else
      @warnings << "代理组 #{group['name']} 的类型 #{type.inspect} 暂不支持，已按 selector 处理。"
      common.merge(
        'type' => 'selector',
        'default' => members.first,
        'interrupt_exist_connections' => true
      )
    end
  end

  def ensure_default_groups!
    node_tags = @proxy_outbounds.map { |outbound| outbound['tag'] }
    auto_tag = unique_tag('auto')
    proxy_tag = unique_tag('proxy')
    @group_name_to_tag['auto'] ||= auto_tag
    @group_name_to_tag['proxy'] ||= proxy_tag

    @group_outbounds << {
      'type' => 'urltest',
      'tag' => auto_tag,
      'outbounds' => node_tags,
      'url' => 'https://www.gstatic.com/generate_204',
      'interval' => '3m',
      'tolerance' => 50,
      'interrupt_exist_connections' => true
    }
    @group_outbounds << {
      'type' => 'selector',
      'tag' => proxy_tag,
      'outbounds' => [auto_tag, *node_tags, 'direct'],
      'default' => auto_tag,
      'interrupt_exist_connections' => true
    }
  end

  def convert_rules
    rules = []
    final_tag = nil

    Array(@document['rules']).each do |raw_rule|
      next unless raw_rule.is_a?(String)

      parts = raw_rule.split(/\s*,\s*/)
      type = parts[0].to_s.upcase

      case type
      when 'DOMAIN'
        rules << outbound_rule('domain', parts[1], parts[2])
      when 'DOMAIN-SUFFIX'
        rules << outbound_rule('domain_suffix', parts[1], parts[2])
      when 'DOMAIN-KEYWORD'
        rules << outbound_rule('domain_keyword', parts[1], parts[2])
      when 'DOMAIN-REGEX'
        rules << outbound_rule('domain_regex', parts[1], parts[2])
      when 'IP-CIDR', 'IP-CIDR6'
        rules << outbound_rule('ip_cidr', parts[1], parts[2])
      when 'SRC-IP-CIDR'
        rules << outbound_rule('source_ip_cidr', parts[1], parts[2])
      when 'SRC-PORT'
        rules << port_rule('source_port', 'source_port_range', parts[1], parts[2])
      when 'DST-PORT', 'IN-PORT'
        rules << port_rule('port', 'port_range', parts[1], parts[2])
      when 'NETWORK'
        rules << outbound_rule('network', parts[1].to_s.downcase, parts[2], wrap: true)
      when 'PROCESS-NAME'
        if @options[:sfm]
          @warnings << "规则 #{raw_rule} 依赖 process_name，SFM/macOS 图形客户端无权限支持，已跳过。"
        else
          rules << outbound_rule('process_name', parts[1], parts[2], wrap: true)
        end
      when 'PROCESS-PATH'
        if @options[:sfm]
          @warnings << "规则 #{raw_rule} 依赖 process_path，SFM/macOS 图形客户端无权限支持，已跳过。"
        else
          rules << outbound_rule('process_path', parts[1], parts[2], wrap: true)
        end
      when 'GEOIP'
        rules << convert_geoip_rule(parts[1], parts[2])
      when 'GEOSITE'
        rules << convert_geosite_rule(parts[1], parts[2])
      when 'MATCH', 'FINAL'
        final_tag = resolve_outbound(parts[1])
        @warnings << "规则 #{raw_rule} 指向了不存在的代理组/节点，已忽略 MATCH。" unless final_tag
      when 'RULE-SET', 'AND', 'OR', 'NOT', 'SUB-RULE', 'SCRIPT', 'IP-ASN'
        @warnings << "规则 #{raw_rule} 暂不支持，已跳过。"
      else
        @warnings << "规则 #{raw_rule} 未识别，已跳过。"
      end
    end

    [rules.compact, final_tag]
  end

  def convert_geoip_rule(value, target)
    country = value.to_s.downcase
    outbound = resolve_outbound(target)
    unless outbound
      @warnings << "规则目标 #{target.inspect} 不存在，已跳过。"
      return nil
    end

    return route_outbound('direct', 'ip_is_private', true) if %w[lan private].include?(country) && outbound == 'direct'
    return route_outbound(outbound, 'ip_is_private', true) if %w[lan private].include?(country)

    tag = ensure_remote_rule_set('geoip', country)
    {
      'rule_set' => [tag],
      'action' => 'route',
      'outbound' => outbound
    }
  end

  def convert_geosite_rule(value, target)
    outbound = resolve_outbound(target)
    unless outbound
      @warnings << "规则目标 #{target.inspect} 不存在，已跳过。"
      return nil
    end

    tag = ensure_remote_rule_set('geosite', value.to_s.downcase)
    {
      'rule_set' => [tag],
      'action' => 'route',
      'outbound' => outbound
    }
  end

  def ensure_remote_rule_set(kind, value)
    key = "#{kind}:#{value}"
    return @rule_sets[key]['tag'] if @rule_sets[key]

    tag = "#{kind}-#{value}"
    url =
      if kind == 'geoip'
        "#{GEOIP_BASE}/geoip-#{value}.srs"
      else
        "#{GEOSITE_BASE}/geosite-#{value}.srs"
      end

    @rule_sets[key] = {
      'type' => 'remote',
      'tag' => tag,
      'format' => 'binary',
      'url' => url,
      'update_interval' => '1d'
    }
    tag
  end

  def attach_rule_set_download_detours!(proxy_detour)
    return if proxy_detour.nil?

    @rule_sets.each_value do |rule_set|
      next unless rule_set['type'] == 'remote'

      rule_set['download_detour'] = proxy_detour
    end
  end

  def build_dns(proxy_detour)
    remote = {
      'type' => 'https',
      'tag' => 'remote-dns',
      'server' => 'cloudflare-dns.com',
      'server_port' => 443,
      'path' => '/dns-query',
      'tls' => {
        'enabled' => true,
        'server_name' => 'cloudflare-dns.com'
      },
      'domain_resolver' => 'local-dns'
    }
    remote['detour'] = proxy_detour if proxy_detour

    {
      'servers' => [
        {
          'type' => 'local',
          'tag' => 'local-dns'
        },
        remote
      ],
      'strategy' => 'prefer_ipv4',
      'final' => 'remote-dns'
    }
  end

  def build_inbounds
    mixed_inbound = {
      'type' => 'mixed',
      'tag' => 'mixed-in',
      'listen' => '127.0.0.1',
      'listen_port' => @options[:mixed_port]
    }

    tun_inbound = {
      'type' => 'tun',
      'tag' => 'tun-in',
      'address' => [
        '172.19.0.1/30',
        'fdfe:dcba:9876::1/126'
      ],
      'mtu' => 9000,
      'auto_route' => true,
      'stack' => 'system'
    }

    if @options[:sfm]
      tun_inbound['platform'] = {
        'http_proxy' => {
          'enabled' => true,
          'server' => '127.0.0.1',
          'server_port' => @options[:mixed_port]
        }
      }
    else
      mixed_inbound['set_system_proxy'] = true
    end

    [mixed_inbound, tun_inbound]
  end

  def build_experimental
    {
      'cache_file' => {
        'enabled' => true,
        'path' => 'cache.db'
      },
      'clash_api' => {
        'external_controller' => "127.0.0.1:#{@options[:api_port]}",
        'external_ui' => 'dashboard',
        'default_mode' => 'Rule'
      }
    }
  end

  def build_outbounds
    [
      *@group_outbounds,
      *@proxy_outbounds,
      {
        'type' => 'direct',
        'tag' => 'direct'
      },
      {
        'type' => 'block',
        'tag' => 'block'
      }
    ]
  end

  def build_route(translated_rules, final_tag)
    rules = [
      {
        'action' => 'sniff'
      },
      {
        'type' => 'logical',
        'mode' => 'or',
        'rules' => [
          { 'protocol' => ['dns'] },
          { 'port' => [53] }
        ],
        'action' => 'hijack-dns'
      },
      {
        'ip_is_private' => true,
        'action' => 'route',
        'outbound' => 'direct'
      },
      *translated_rules
    ]

    route = {
      'rules' => rules,
      'final' => final_tag,
      'auto_detect_interface' => true,
      'default_domain_resolver' => 'local-dns'
    }
    route['rule_set'] = @rule_sets.values unless @rule_sets.empty?
    route
  end

  def infer_final_tag
    preferred = %w[proxy Proxy PROXY 节点选择 GLOBAL global auto Auto]
    preferred.each do |name|
      tag = resolve_outbound(name)
      return tag if tag
    end

    first_group = @group_outbounds.first
    return first_group['tag'] if first_group

    @proxy_outbounds.first['tag']
  end

  def infer_proxy_detour(final_tag)
    return final_tag if final_tag && !%w[direct block].include?(final_tag)

    first_group = @group_outbounds.find { |outbound| !%w[direct block].include?(outbound['tag']) }
    return first_group['tag'] if first_group

    first_proxy = @proxy_outbounds.first
    first_proxy && first_proxy['tag']
  end

  def expand_group_members(group)
    names = []
    names.concat(filtered_provider_nodes(group))
    names.concat(Array(group['proxies']))
    names = [*all_proxy_names, *names] if truthy?(group['include-all'])
    names = apply_name_filters(names, group['filter'], group['exclude-filter'])

    names.each_with_object([]) do |name, result|
      tag = resolve_outbound(name)
      unless tag
        @warnings << "代理组 #{group['name']} 引用了不存在的成员 #{name.inspect}，已忽略。"
        next
      end
      result << tag unless result.include?(tag)
    end
  end

  def filtered_provider_nodes(group)
    Array(group['use']).flat_map do |provider_name|
      proxy_names = @provider_proxy_names[provider_name.to_s]
      if proxy_names.nil?
        @warnings << "代理组 #{group['name']} 引用了不存在的 proxy-provider #{provider_name.inspect}。"
        next []
      end
      proxy_names
    end
  end

  def apply_name_filters(names, include_filter, exclude_filter)
    result = names.dup
    if include_filter && !include_filter.to_s.empty?
      regexp = Regexp.new(include_filter.to_s)
      result.select! { |name| regexp.match?(name.to_s) }
    end
    if exclude_filter && !exclude_filter.to_s.empty?
      regexp = Regexp.new(exclude_filter.to_s)
      result.reject! { |name| regexp.match?(name.to_s) }
    end
    result
  rescue RegexpError => e
    @warnings << "分组过滤正则无效：#{e.message}"
    names
  end

  def all_proxy_names
    @proxy_name_to_tag.keys
  end

  def resolve_outbound(name)
    value = name.to_s
    return 'direct' if value.casecmp('DIRECT').zero?
    return 'block' if %w[REJECT REJECT-DROP].any? { |keyword| value.casecmp(keyword).zero? }
    return @group_name_to_tag[value] if @group_name_to_tag[value]
    return @proxy_name_to_tag[value] if @proxy_name_to_tag[value]

    downcased = value.downcase
    @group_name_to_tag.each { |key, tag| return tag if key.downcase == downcased }
    @proxy_name_to_tag.each { |key, tag| return tag if key.downcase == downcased }
    nil
  end

  def outbound_rule(field, value, target, wrap: false)
    outbound = resolve_outbound(target)
    unless outbound
      @warnings << "规则目标 #{target.inspect} 不存在，已跳过。"
      return nil
    end

    payload = wrap ? [value] : [value]
    {
      field => payload,
      'action' => 'route',
      'outbound' => outbound
    }
  end

  def route_outbound(target, field, value)
    {
      field => value,
      'action' => 'route',
      'outbound' => target
    }
  end

  def port_rule(port_field, range_field, raw_value, target)
    outbound = resolve_outbound(target)
    unless outbound
      @warnings << "规则目标 #{target.inspect} 不存在，已跳过。"
      return nil
    end

    value = raw_value.to_s
    matcher =
      if value.include?('-') || value.include?(':')
        { range_field => [value.tr('-', ':')] }
      else
        { port_field => [integer_or_nil(value) || value.to_i] }
      end

    matcher.merge(
      'action' => 'route',
      'outbound' => outbound
    )
  end

  def convert_shadowsocks(proxy)
    outbound = {
      'type' => 'shadowsocks',
      'server' => required(proxy, 'server'),
      'server_port' => integer_required(proxy, 'port'),
      'method' => required(proxy, 'cipher'),
      'password' => required(proxy, 'password')
    }
    outbound['plugin'] = proxy['plugin'] if proxy['plugin']
    plugin_opts = encode_plugin_opts(proxy['plugin-opts'] || proxy['plugin_opts'])
    outbound['plugin_opts'] = plugin_opts if plugin_opts
    outbound['network'] = 'tcp' if proxy['udp'] == false
    outbound['udp_over_tcp'] = true if truthy?(proxy['udp-over-tcp'] || proxy['udp_over_tcp'])
    outbound
  end

  def convert_trojan(proxy)
    outbound = {
      'type' => 'trojan',
      'server' => required(proxy, 'server'),
      'server_port' => integer_required(proxy, 'port'),
      'password' => required(proxy, 'password'),
      'tls' => build_tls(proxy, force: true)
    }
    outbound['network'] = 'tcp' if proxy['udp'] == false
    transport = build_transport(proxy)
    outbound['transport'] = transport if transport
    outbound
  end

  def convert_vmess(proxy)
    outbound = {
      'type' => 'vmess',
      'server' => required(proxy, 'server'),
      'server_port' => integer_required(proxy, 'port'),
      'uuid' => required(proxy, 'uuid')
    }
    outbound['security'] = proxy['cipher'] if proxy['cipher']
    outbound['alter_id'] = integer_or_nil(proxy['alterId'] || proxy['alter_id']) if proxy['alterId'] || proxy['alter_id']
    outbound['tls'] = build_tls(proxy, force: truthy?(proxy['tls'])) if truthy?(proxy['tls']) || proxy['reality-opts'] || proxy['client-fingerprint']
    outbound['network'] = 'tcp' if proxy['udp'] == false
    packet_encoding = packet_encoding_for(proxy)
    outbound['packet_encoding'] = packet_encoding if packet_encoding
    transport = build_transport(proxy)
    outbound['transport'] = transport if transport
    outbound
  end

  def convert_vless(proxy)
    outbound = {
      'type' => 'vless',
      'server' => required(proxy, 'server'),
      'server_port' => integer_required(proxy, 'port'),
      'uuid' => required(proxy, 'uuid')
    }
    outbound['flow'] = proxy['flow'] if proxy['flow']
    outbound['tls'] = build_tls(proxy, force: truthy?(proxy['tls']) || proxy['reality-opts'] || proxy['flow']) if truthy?(proxy['tls']) || proxy['reality-opts'] || proxy['flow'] || proxy['client-fingerprint']
    outbound['network'] = 'tcp' if proxy['udp'] == false
    packet_encoding = packet_encoding_for(proxy)
    outbound['packet_encoding'] = packet_encoding if packet_encoding
    transport = build_transport(proxy)
    outbound['transport'] = transport if transport
    outbound
  end

  def convert_hysteria(proxy)
    outbound = {
      'type' => 'hysteria',
      'server' => required(proxy, 'server'),
      'server_port' => integer_required(proxy, 'port'),
      'up_mbps' => Mbps.parse(proxy['up'] || proxy['up-speed'] || proxy['up_speed']),
      'down_mbps' => Mbps.parse(proxy['down'] || proxy['down-speed'] || proxy['down_speed']),
      'tls' => build_tls(proxy, force: true)
    }
    outbound['auth_str'] = proxy['auth-str'] || proxy['auth_str'] || proxy['auth']
    outbound['obfs'] = proxy['obfs'] if proxy['obfs']
    outbound['network'] = 'tcp' if proxy['udp'] == false
    outbound
  end

  def convert_hysteria2(proxy)
    outbound = {
      'type' => 'hysteria2',
      'server' => required(proxy, 'server'),
      'server_port' => integer_required(proxy, 'port'),
      'tls' => build_tls(proxy, force: true)
    }
    outbound['password'] = proxy['password'] || proxy['auth'] || proxy['auth-str'] || proxy['auth_str']
    outbound['up_mbps'] = Mbps.parse(proxy['up'] || proxy['up-speed'] || proxy['up_speed']) if proxy['up'] || proxy['up-speed'] || proxy['up_speed']
    outbound['down_mbps'] = Mbps.parse(proxy['down'] || proxy['down-speed'] || proxy['down_speed']) if proxy['down'] || proxy['down-speed'] || proxy['down_speed']
    outbound['obfs'] = {
      'type' => proxy['obfs'],
      'password' => proxy['obfs-password'] || proxy['obfs_password']
    } if proxy['obfs']
    outbound['network'] = 'tcp' if proxy['udp'] == false
    outbound
  end

  def convert_tuic(proxy)
    outbound = {
      'type' => 'tuic',
      'server' => required(proxy, 'server'),
      'server_port' => integer_required(proxy, 'port'),
      'uuid' => required(proxy, 'uuid'),
      'tls' => build_tls(proxy, force: true)
    }
    outbound['password'] = proxy['password'] if proxy['password']
    outbound['congestion_control'] = proxy['congestion-controller'] || proxy['congestion_control'] if proxy['congestion-controller'] || proxy['congestion_control']
    outbound['udp_relay_mode'] = proxy['udp-relay-mode'] || proxy['udp_relay_mode'] if proxy['udp-relay-mode'] || proxy['udp_relay_mode']
    outbound['udp_over_stream'] = true if truthy?(proxy['udp-over-stream'] || proxy['udp_over_stream'])
    outbound['zero_rtt_handshake'] = true if truthy?(proxy['reduce-rtt'] || proxy['reduce_rtt'])
    outbound['heartbeat'] = duration(proxy['heartbeat']) if proxy['heartbeat']
    outbound['network'] = 'tcp' if proxy['udp'] == false
    outbound
  end

  def convert_socks(proxy)
    outbound = {
      'type' => 'socks',
      'server' => required(proxy, 'server'),
      'server_port' => integer_required(proxy, 'port')
    }
    outbound['version'] = proxy['version'].to_s if proxy['version']
    outbound['username'] = proxy['username'] if proxy['username']
    outbound['password'] = proxy['password'] if proxy['password']
    outbound['network'] = 'tcp' if proxy['udp'] == false
    outbound['udp_over_tcp'] = true if truthy?(proxy['udp-over-tcp'] || proxy['udp_over_tcp'])
    outbound
  end

  def convert_http(proxy)
    outbound = {
      'type' => 'http',
      'server' => required(proxy, 'server'),
      'server_port' => integer_required(proxy, 'port')
    }
    outbound['username'] = proxy['username'] if proxy['username']
    outbound['password'] = proxy['password'] if proxy['password']
    outbound['path'] = proxy['path'] if proxy['path']
    outbound['headers'] = proxy['headers'] if proxy['headers'].is_a?(Hash)
    outbound['tls'] = build_tls(proxy, force: truthy?(proxy['tls'])) if truthy?(proxy['tls']) || proxy['client-fingerprint']
    outbound
  end

  def build_tls(proxy, force: false)
    return nil unless force || truthy?(proxy['tls']) || proxy['sni'] || proxy['servername'] || proxy['skip-cert-verify'] || proxy['reality-opts'] || proxy['reality_opts'] || proxy['client-fingerprint']

    tls = {
      'enabled' => true
    }

    server_name = proxy['servername'] || proxy['server-name'] || proxy['sni'] || proxy['peer'] || proxy['host']
    tls['server_name'] = server_name if server_name && !server_name.to_s.empty?
    tls['insecure'] = true if truthy?(proxy['skip-cert-verify'] || proxy['skip_cert_verify'])
    alpn = normalize_array(proxy['alpn'])
    tls['alpn'] = alpn unless alpn.empty?

    fingerprint = proxy['client-fingerprint'] || proxy['client_fingerprint'] || proxy['fingerprint']
    if fingerprint && !fingerprint.to_s.empty?
      tls['utls'] = {
        'enabled' => true,
        'fingerprint' => fingerprint
      }
    end

    reality = proxy['reality-opts'] || proxy['reality_opts']
    if reality.is_a?(Hash)
      tls['reality'] = {
        'enabled' => true,
        'public_key' => reality['public-key'] || reality['public_key'],
        'short_id' => reality['short-id'] || reality['short_id']
      }
      tls['server_name'] ||= reality['servername'] || reality['server_name']
    end

    prune(tls)
  end

  def build_transport(proxy)
    network = proxy['network'].to_s.downcase

    case network
    when 'ws', 'websocket'
      opts = proxy['ws-opts'] || proxy['ws_opts'] || {}
      {
        'type' => 'ws',
        'path' => opts['path'],
        'headers' => normalize_headers(opts['headers']),
        'max_early_data' => integer_or_nil(opts['max-early-data'] || opts['max_early_data']),
        'early_data_header_name' => opts['early-data-header-name'] || opts['early_data_header_name']
      }
    when 'grpc'
      opts = proxy['grpc-opts'] || proxy['grpc_opts'] || {}
      {
        'type' => 'grpc',
        'service_name' => opts['grpc-service-name'] || opts['grpc_service_name'] || proxy['grpc-service-name'] || proxy['grpc_service_name']
      }
    when 'h2', 'http'
      opts = proxy['h2-opts'] || proxy['h2_opts'] || proxy['http-opts'] || proxy['http_opts'] || {}
      {
        'type' => 'http',
        'host' => normalize_array(opts['host']),
        'path' => opts['path'],
        'headers' => normalize_headers(opts['headers'])
      }
    when 'httpupgrade', 'http-upgrade'
      opts = proxy['http-opts'] || proxy['http_opts'] || {}
      {
        'type' => 'httpupgrade',
        'host' => opts['host'],
        'path' => opts['path'],
        'headers' => normalize_headers(opts['headers'])
      }
    when 'quic'
      { 'type' => 'quic' }
    else
      nil
    end
  end

  def packet_encoding_for(proxy)
    return proxy['packet-encoding'] if proxy['packet-encoding']
    return proxy['packet_encoding'] if proxy['packet_encoding']
    return 'xudp' if truthy?(proxy['xudp'])
    return 'packetaddr' if truthy?(proxy['packet-addr'] || proxy['packet_addr'])

    nil
  end

  def normalize_headers(headers)
    return nil unless headers.is_a?(Hash)

    headers.each_with_object({}) do |(key, value), result|
      result[key.to_s] = value
    end
  end

  def encode_plugin_opts(opts)
    case opts
    when nil
      nil
    when String
      opts
    when Hash
      opts.each_with_object([]) do |(key, value), result|
        next if value.nil? || value == false
        if value == true
          result << key.to_s
        else
          result << "#{key}=#{value}"
        end
      end.join(';')
    else
      opts.to_s
    end
  end

  def unique_tag(seed)
    base = seed.to_s.strip
    base = 'proxy' if base.empty?
    candidate = base
    index = 2
    while @seen_tags.include?(candidate)
      candidate = "#{base} [#{index}]"
      index += 1
    end
    @seen_tags << candidate
    candidate
  end

  def required(hash, key)
    value = hash[key]
    raise "#{key} 缺失" if value.nil? || value.to_s.empty?

    value
  end

  def integer_required(hash, key)
    value = integer_or_nil(hash[key])
    raise "#{key} 不是有效整数" if value.nil?

    value
  end

  def integer_or_nil(value)
    return value if value.is_a?(Integer)
    return nil if value.nil? || value.to_s.empty?

    Integer(value.to_s)
  rescue ArgumentError
    nil
  end

  def duration(value)
    return nil if value.nil? || value.to_s.empty?
    return "#{value}s" if value.is_a?(Integer)

    text = value.to_s.strip
    return "#{text}s" if text.match?(/\A\d+\z/)

    text
  end

  def normalize_array(value)
    case value
    when nil
      []
    when Array
      value.compact.map(&:to_s)
    else
      value.to_s.split(/\s*,\s*/).reject(&:empty?)
    end
  end

  def truthy?(value)
    case value
    when true then true
    when false, nil then false
    else
      !%w[false 0 no off].include?(value.to_s.downcase)
    end
  end

  def prune(value)
    case value
    when Hash
      value.each_with_object({}) do |(key, inner), result|
        cleaned = prune(inner)
        next if cleaned.nil?
        next if cleaned.respond_to?(:empty?) && cleaned.empty?

        result[key] = cleaned
      end
    when Array
      value.map { |inner| prune(inner) }.compact.reject { |inner| inner.respond_to?(:empty?) && inner.empty? }
    else
      value
    end
  end

  def parse_document(text)
    self.class.parse_document(text)
  end

  def self.parse_document(text)
    return {} if text.nil? || text.strip.empty?

    stripped = text.lstrip
    if stripped.start_with?('{', '[')
      parsed_json = JSON.parse(text)
      return parsed_json if parsed_json.is_a?(Hash)
    end

    parsed = YAML.load(text)
    return parsed if parsed.is_a?(Hash)

    decoded = try_decode_base64(text)
    decoded_stripped = decoded.lstrip
    if decoded_stripped.start_with?('{', '[')
      parsed_json = JSON.parse(decoded)
      return parsed_json if parsed_json.is_a?(Hash)
    end

    parsed = YAML.load(decoded)
    return parsed if parsed.is_a?(Hash)

    raise '订阅内容不是可解析的 Clash YAML。'
  rescue JSON::ParserError, Psych::SyntaxError
    decoded = try_decode_base64(text)
    decoded_stripped = decoded.lstrip
    if decoded_stripped.start_with?('{', '[')
      parsed_json = JSON.parse(decoded)
      return parsed_json if parsed_json.is_a?(Hash)
    end

    parsed = YAML.load(decoded)
    return parsed if parsed.is_a?(Hash)

    raise '订阅内容不是可解析的 Clash YAML。'
  end

  def self.try_decode_base64(text)
    stripped = text.gsub(/\s+/, '')
    return text unless stripped.match?(/\A[A-Za-z0-9+\/=]+\z/)

    Base64.decode64(stripped)
  rescue ArgumentError
    text
  end
end

def already_sing_box_config?(document)
  return false unless document.is_a?(Hash)

  document.key?('inbounds') && document.key?('outbounds') && !document.key?('proxies')
end

def compact_object(value)
  case value
  when Hash
    value.each_with_object({}) do |(key, inner), result|
      cleaned = compact_object(inner)
      next if cleaned.nil?
      next if cleaned.respond_to?(:empty?) && cleaned.empty?

      result[key] = cleaned
    end
  when Array
    value.map { |inner| compact_object(inner) }.compact.reject { |inner| inner.respond_to?(:empty?) && inner.empty? }
  else
    value
  end
end

def parse_host_port(raw, default_port)
  uri = URI.parse(raw.include?('://') ? raw : "//#{raw}")
  host = uri.host || raw
  port = uri.port || default_port
  [host, port]
rescue URI::InvalidURIError
  [raw, default_port]
end

def rewrite_dns_rule_server!(rules, target_tag, action)
  case rules
  when Array
    rules.each { |rule| rewrite_dns_rule_server!(rule, target_tag, action) }
  when Hash
    if rules['server'] == target_tag
      rules.delete('server')
      action.each { |key, value| rules[key] = value }
    end
    rewrite_dns_rule_server!(rules['rules'], target_tag, action) if rules['rules']
  end
end

def dns_rule_keys_excluding(rule, *keys)
  rule.keys - keys
end

def apply_domain_resolver_to_outbounds!(outbounds, target_tags, resolver)
  Array(outbounds).each do |outbound|
    next unless outbound.is_a?(Hash)
    next unless target_tags.include?(outbound['tag'])

    outbound['domain_resolver'] ||= resolver
  end
end

def migrate_legacy_dns_server(server, fakeip_options, warnings)
  return server unless server.is_a?(Hash) && server['address']

  address = server['address'].to_s
  migrated = server.dup
  migrated.delete('address')
  migrated.delete('address_resolver')
  migrated.delete('address_strategy')

  case address
  when 'local'
    migrated['type'] = 'local'
  when 'fakeip'
    migrated['type'] = 'fakeip'
    migrated.delete('strategy')
    migrated['inet4_range'] ||= fakeip_options['inet4_range'] if fakeip_options.is_a?(Hash)
    migrated['inet6_range'] ||= fakeip_options['inet6_range'] if fakeip_options.is_a?(Hash)
    warnings << '已把旧的 dns.fakeip/address=fakeip 迁移到新的 type=fakeip 服务器格式。'
  when /\Ahttps:\/\//
    uri = URI.parse(address)
    migrated['type'] = 'https'
    migrated['server'] = uri.host
    migrated['server_port'] = uri.port if uri.port && uri.port != 443
    path = uri.path.to_s
    path = "#{path}?#{uri.query}" if uri.query && !uri.query.empty?
    migrated['path'] = path unless path.empty? || path == '/'
    migrated['domain_resolver'] = server['address_resolver'] if server['address_resolver']
  when /\Atls:\/\//
    raw = address.sub(/\Atls:\/\//, '')
    host, port = parse_host_port(raw, 853)
    migrated['type'] = 'tls'
    migrated['server'] = host
    migrated['server_port'] = port if port != 853
    migrated['domain_resolver'] = server['address_resolver'] if server['address_resolver']
  when /\Atcp:\/\//
    raw = address.sub(/\Atcp:\/\//, '')
    host, port = parse_host_port(raw, 53)
    migrated['type'] = 'tcp'
    migrated['server'] = host
    migrated['server_port'] = port if port != 53
    migrated['domain_resolver'] = server['address_resolver'] if server['address_resolver']
  when /\Aquic:\/\//
    raw = address.sub(/\Aquic:\/\//, '')
    host, port = parse_host_port(raw, 853)
    migrated['type'] = 'quic'
    migrated['server'] = host
    migrated['server_port'] = port if port != 853
    migrated['domain_resolver'] = server['address_resolver'] if server['address_resolver']
  when /\Ah3:\/\//
    uri = URI.parse(address.sub(/\Ah3:\/\//, 'https://'))
    migrated['type'] = 'http3'
    migrated['server'] = uri.host
    migrated['server_port'] = uri.port if uri.port && uri.port != 443
    path = uri.path.to_s
    path = "#{path}?#{uri.query}" if uri.query && !uri.query.empty?
    migrated['path'] = path unless path.empty? || path == '/'
    migrated['domain_resolver'] = server['address_resolver'] if server['address_resolver']
  when /\Adhcp:\/\//
    interface = address.sub(/\Adhcp:\/\//, '')
    migrated['type'] = 'dhcp'
    migrated['interface'] = interface unless interface.empty? || interface == 'auto'
  when /\Arcode:\/\//
    rcode = address.sub(/\Arcode:\/\//, '').upcase
    mapped =
      {
        'SUCCESS' => 'NOERROR',
        'FORMAT_ERROR' => 'FORMERR',
        'SERVER_FAILURE' => 'SERVFAIL',
        'NAME_ERROR' => 'NXDOMAIN',
        'NOT_IMPLEMENTED' => 'NOTIMP',
        'REFUSED' => 'REFUSED'
      }[rcode] || rcode
    return [:rcode, migrated['tag'], mapped]
  else
    host, port = parse_host_port(address.sub(/\Audp:\/\//, ''), 53)
    migrated['type'] = 'udp'
    migrated['server'] = host
    migrated['server_port'] = port if port != 53
    migrated['domain_resolver'] = server['address_resolver'] if server['address_resolver']
  end

  if migrated['detour'] == 'direct'
    migrated.delete('detour')
    warnings << "已移除 DNS server #{migrated['tag'] || address} 上无效的 detour=direct。"
  end

  compact_object(migrated)
rescue URI::InvalidURIError => e
  warnings << "保留未迁移的旧 DNS server #{address.inspect}：#{e.message}"
  server
end

def normalize_sing_box_config!(document)
  warnings = []
  dns = document['dns']
  return warnings unless dns.is_a?(Hash)
  document['route'] ||= {}

  fakeip_options = dns['fakeip']
  rcode_migrations = []

  dns['servers'] = Array(dns['servers']).each_with_object([]) do |server, result|
    migrated = migrate_legacy_dns_server(server, fakeip_options, warnings)
    if migrated.is_a?(Array) && migrated[0] == :rcode
      rcode_migrations << migrated
    else
      result << migrated
    end
  end

  rcode_migrations.each do |_kind, tag, rcode|
    next if tag.to_s.empty?

    rewrite_dns_rule_server!(dns['rules'], tag, {
      'action' => 'predefined',
      'rcode' => rcode
    })
    warnings << "已把旧的 rcode DNS server #{tag} 迁移为 predefined DNS rule action。"
  end

  dns['rules'] = Array(dns['rules']).each_with_object([]) do |rule, result|
    unless rule.is_a?(Hash) && rule.key?('outbound') && rule.key?('server')
      result << rule
      next
    end

    outbound_value = rule['outbound']
    outbound_tags = Array(outbound_value).map(&:to_s)
    rule_specific_keys = dns_rule_keys_excluding(rule, 'outbound', 'server', 'action', 'strategy', 'disable_cache', 'disable_optimistic_cache', 'rewrite_ttl', 'client_subnet')
    resolver =
      if rule.keys.any? { |key| %w[strategy disable_cache disable_optimistic_cache rewrite_ttl client_subnet].include?(key) }
        compact_object({
          'server' => rule['server'],
          'strategy' => rule['strategy'],
          'disable_cache' => rule['disable_cache'],
          'disable_optimistic_cache' => rule['disable_optimistic_cache'],
          'rewrite_ttl' => rule['rewrite_ttl'],
          'client_subnet' => rule['client_subnet']
        })
      else
        rule['server']
      end

    if outbound_tags == ['any'] && rule_specific_keys.empty?
      document['route']['default_domain_resolver'] ||= resolver
      warnings << '已把 dns.rules 里的 outbound:any 迁移到 route.default_domain_resolver。'
      next
    end

    if rule_specific_keys.empty?
      apply_domain_resolver_to_outbounds!(document['outbounds'], outbound_tags, resolver)
      warnings << "已把 dns.rules 里的 outbound 规则迁移到对应 outbounds[*].domain_resolver：#{outbound_tags.join(', ')}。"
      next
    end

    result << rule
  end

  dns.delete('fakeip')
  document['route'] = compact_object(document['route'])
  document['dns'] = compact_object(dns)
  warnings.uniq
end

def rewrite_outbound_references!(node, replacements)
  case node
  when Array
    node.each { |item| rewrite_outbound_references!(item, replacements) }
  when Hash
    node.each do |key, value|
      case key
      when 'outbound', 'default', 'detour', 'external_ui_download_detour'
        node[key] = replacements.fetch(value, value) if value.is_a?(String)
      when 'outbounds'
        if value.is_a?(Array)
          node[key] = value.map { |item| item.is_a?(String) ? replacements.fetch(item, item) : item }
        else
          rewrite_outbound_references!(value, replacements)
        end
      else
        rewrite_outbound_references!(value, replacements)
      end
    end
  end
end

def normalize_power_save_selector!(outbound, fixed_tag, removed_tags)
  return unless outbound['type'] == 'selector'

  members = Array(outbound['outbounds']).reject { |tag| removed_tags.include?(tag) }.uniq
  members = [fixed_tag] if outbound['tag'] == '节点选择' || members.empty?
  outbound['outbounds'] = members

  outbound['default'] =
    if outbound['tag'] == '节点选择'
      fixed_tag
    elsif members.include?(outbound['default'])
      outbound['default']
    else
      members.first
    end
end

def normalize_tag_lookup(tag)
  tag.to_s.gsub(/\s+/, '')
end

def resolve_power_save_fixed_tag(outbounds, fixed_tag)
  exact_match = outbounds.find { |outbound| outbound['tag'] == fixed_tag }
  return fixed_tag if exact_match

  normalized = normalize_tag_lookup(fixed_tag)
  matches = outbounds.map { |outbound| outbound['tag'] }.compact.select { |tag| normalize_tag_lookup(tag) == normalized }.uniq
  raise "省电计划指定的固定节点不存在：#{fixed_tag}" if matches.empty?
  raise "省电计划指定的固定节点匹配到多个候选：#{matches.join(' / ')}" if matches.length > 1

  matches.first
end

def apply_power_save_plan!(document, fixed_tag)
  outbounds = Array(document['outbounds'])
  fixed_tag = resolve_power_save_fixed_tag(outbounds, fixed_tag)

  removed_tags = outbounds.select { |outbound| outbound['type'] == 'urltest' }.map { |outbound| outbound['tag'] }
  document['outbounds'] = outbounds.reject { |outbound| removed_tags.include?(outbound['tag']) }

  replacements = removed_tags.each_with_object('节点选择' => fixed_tag) { |tag, result| result[tag] = fixed_tag }
  rewrite_outbound_references!(document, replacements)

  Array(document['outbounds']).each do |outbound|
    normalize_power_save_selector!(outbound, fixed_tag, removed_tags)
  end

  route = document['route'] ||= {}
  route['final'] = fixed_tag

  document
end

module Mbps
  module_function

  def parse(value)
    return nil if value.nil? || value.to_s.empty?
    return value if value.is_a?(Integer)

    text = value.to_s.strip
    return text.to_i if text.match?(/\A\d+\z/)

    match = text.match(/\A(\d+(?:\.\d+)?)\s*([KMGT]?)([bB])ps\z/i)
    raise "无法解析带宽 #{value.inspect}" unless match

    number = match[1].to_f
    unit = match[2].upcase
    bytes = match[3] == 'B'
    multiplier =
      case unit
      when '' then 1.0 / 1_000_000
      when 'K' then 1.0 / 1_000
      when 'M' then 1.0
      when 'G' then 1_000.0
      when 'T' then 1_000_000.0
      else 1.0
      end
    number *= 8 if bytes
    number *= multiplier
    number.round
  end
end

options = {
  mixed_port: 7890,
  api_port: 9090
}

parser = OptionParser.new do |opts|
  opts.banner = '用法: ruby clash_to_singbox.rb --url <clash订阅链接> [--out config.json]'

  opts.on('--url URL', 'Clash 机场订阅链接') { |value| options[:url] = value }
  opts.on('--file PATH', '本地 Clash YAML 文件') { |value| options[:file] = value }
  opts.on('--out PATH', '输出路径，默认 config.json') { |value| options[:out] = value }
  opts.on('--sfm', '生成适配 SFM/macOS 图形客户端的配置') { options[:sfm] = true }
  opts.on('--power-save-fixed TAG', '实施省电计划并固定到指定节点标签') { |value| options[:power_save_fixed] = value }
  opts.on('--mixed-port PORT', Integer, 'mixed 入站端口，默认 7890') { |value| options[:mixed_port] = value }
  opts.on('--api-port PORT', Integer, 'Clash API 端口，默认 9090') { |value| options[:api_port] = value }
  opts.on('--header HEADER', '额外请求头，格式 Name: Value，可重复') do |value|
    options[:headers] ||= {}
    name, header_value = value.split(':', 2)
    raise OptionParser::InvalidArgument, 'header 格式必须是 Name: Value' if header_value.nil?

    options[:headers][name.strip] = header_value.strip
  end
end

parser.parse!(ARGV)

if options[:url].nil? && options[:file].nil?
  warn parser.to_s
  exit 1
end

text =
  if options[:file]
    options[:source_dir] = File.dirname(File.expand_path(options[:file]))
    File.read(options[:file])
  else
    options[:fetcher] = Fetcher.new(options[:headers] || {})
    options[:fetcher].fetch(options[:url])
  end

options[:fetcher] ||= Fetcher.new(options[:headers] || {})
document = ClashToSingBox.parse_document(text)
if already_sing_box_config?(document)
  migration_warnings = normalize_sing_box_config!(document)
  converter = nil
  config = document
else
  migration_warnings = []
  converter = ClashToSingBox.new(document, options)
  config = converter.convert
end

apply_power_save_plan!(config, options[:power_save_fixed]) if options[:power_save_fixed]

output = JSON.pretty_generate(config)
out_path = options[:out] || 'config.json'

if out_path == '-'
  puts output
else
  FileUtils.mkdir_p(File.dirname(File.expand_path(out_path)))
  File.write(out_path, output)
end

warn "已生成 sing-box 配置：#{out_path == '-' ? 'STDOUT' : File.expand_path(out_path)}"
if converter
  warn "节点数：#{converter.send(:build_outbounds).count { |outbound| !%w[selector urltest direct block].include?(outbound['type']) }}"
  converter.warnings.each { |message| warn "警告：#{message}" }
else
  warn '检测到订阅已经是 sing-box JSON，已直接格式化输出。'
end
migration_warnings.each { |message| warn "警告：#{message}" }
