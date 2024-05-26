---
title: "单元测试编写指引"
linkTitle: "单元测试编写指引"
weight: 4
---

## 一、单元测试依赖

```xml
<!-- macula平台(cloud、sample或脚手架archetype生成的项目)默认添加，不支持JUnit 4 编写测试 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>

<!-- H2 是一个用 Java 开发的嵌入式数据库，它本身只是一个类库，即只有一个 jar 文件，可以直接嵌入到应用项目中 -->
<!-- 可用于单元测试。启动速度快，而且可以关闭持久化功能，每一个用例执行完随即还原到初始状态 -->
<!-- 按需添加，若使用了macula平台提供的macula-boot-starter-jpa或macula-boot-starter-mybatis-plus则默认添加 -->
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <scope>test</scope>
</dependency>

<!-- 需要使用JUnit 4 编写测试, 请添加下方依赖 -->
<dependency>
    <groupId>org.junit.vintage</groupId>
    <artifactId>junit-vintage-engine</artifactId>
    <scope>test</scope>
    <exclusions>
        <exclusion>
            <groupId>org.hamcrest</groupId>
            <artifactId>hamcrest-core</artifactId>
        </exclusion>
    </exclusions>
</dependency>

```

## 二、单元测试注解

核心注解说明如下：

|  **注解**  |  **描述**  |
| ------------ | ------------ |
|  @SpringBootTest  |  类注解; 用来标记一个测试类，它告诉Spring Boot启动一个完整的应用程序上下文，而不仅仅是一个单一的测试类或测试方法。这个完整的应用程序上下文将包含所有的Spring Bean、配置和依赖项，在没有正式(非test源码包)配置类情况下，程序会从当前包开始，逐级向上查找@SpringBootApplication或@SpringBootConfiguration注解中的配置类，以作为整个应用的入口点，从而简化应用的配置和启动过程，单元测试不建议使用该注解  |
|  @ExtendWith  |  类注解; 代替Junit4的@RunWith注解，用于扩展test能力, 通过提供一系列的扩展点(extension point)来支持用户在执行具体的单测实例前后去做一些环境准备等工作，这部分工作与单测内容无关, 但对于单测的正常执行却至关重要,如@ExtendWith(SpringExtension.class)用来将Spring Test Framework 集成到Junit5测试环境中，提供了Spring单测的上下文环境, 会启动一个用于单测的spring容器, 完成单测中所需的bean对象的构建与自动注入  |
|  @TestConfiguration  |  类注解;  @Configuration类的扩展，用于补充额外的Bean或覆盖已存在的Bean。在不修改正式代码的前提下，使配置更加灵活，与常规的@Configuration类不同，@TestConfiguration注解的类不会被扫描到并用于正常的应用程序配置中，而是只会在测试中使用  |
|  @AutoConfigureMockMvc  |  类注解;  自动配置MockMvc，在集成测试中，用于创建应用程序访问请求，验证程序响应结果  |
|  @MockBean  |  字段注解; 允许在单元测试期间用模拟对象替换实际的 bean，目标对象的所有方法全部mock，不会真实调用  |
|  @SpyBean  |  字段注解; 允许在单元测试期间部分模拟实际的 bean，除了打桩方法是mock对象返回其余都是真实方法调用  |
|  @Test  |  方法注解; 表示方法是测试方法。与JUnit4的@Test注解不同的是，这个注解没有声明任何属性，因为JUnit Jupiter中的测试扩展是基于他们自己的专用注解来操作的。除非被覆盖，否则这些方法可以继承。  |
|  @ParameterizedTest  |  方法注解; 参数化测试可以用不同的参数多次运行测试。测试方法必须声明至少一个将为每次调用提供参数的来源(source)如：@ValueSource，更多参数来源请参阅org.junit.jupiter.params.provider包中的JavaDoc以获取更多信息  |
|  @BeforeAll  |  方法注解; 表示被注解的方法应该在当前类的所有@Test，@ParameterizedTest方法之前执行; 类似于JUnit 4的@BeforeClass。 这样的方法可以继承（除非被隐藏或覆盖），并且必须是静态的（除非使用“per-class”测试实例生命周期）。  |
|  @BeforeEach  |  方法注解; 表示被注解的方法应在当前类的每个@Test，@ParameterizedTest方法之前执行; 类似于JUnit 4的@Before。 除非被覆盖，否则这些方法可以继承。  |
|  @AfterEach  |  方法注解; 表示被注解的方法应在当前类的每个@Test，@ParameterizedTest方法之后执行; 类似于JUnit 4的@After。 除非被覆盖，否则这些方法可以继承。  |
|  @AfterAll  |  方法注解; 表示被注解的方法应该在当前类的所有@Test，@ParameterizedTest方法之后执行; 类似于JUnit 4的@AfterClass。 这样的方法可以继承（除非被隐藏或覆盖），并且必须是静态的（除非使用“per-class”测试实例生命周期）。  |

## 三、单元测试样例

在这个阶段，软件的各层对象各自测试，保障单元逻辑的正确性。

```java
注意：@ExtendWith(SpringExtension.class)只是启动Spring容器，没有启动SpringBoot的内嵌Tomcat容器，提高启动速度，提升单元测试效率。
```

### 1.Mapper类型单元测试

主要进行sql语法及sql执行结果的测试验证

```java
package test.macula.cloud.system;

import com.alibaba.druid.spring.boot.autoconfigure.DruidDataSourceAutoConfigure;
import dev.macula.cloud.system.mapper.SysApiMapper;
import dev.macula.cloud.system.pojo.entity.SysApi;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Autowired;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.TestPropertySource;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {DruidDataSourceAutoConfigure.class,
        com.baomidou.mybatisplus.autoconfigure.MybatisPlusAutoConfiguration.class,
        dev.macula.boot.starter.mp.config.MyBatisPlusAutoConfiguration.class})
@MapperScan(basePackages = "dev.macula.cloud.system.mapper")
@TestPropertySource("classpath:application-test.properties")
public class TestSysApiMapper {

    @Autowired
    private SysApiMapper sysApiMapper;

    @Test
    public void testSelectById(){
        Long mockId = 1248L;
        SysApi sysApi = sysApiMapper.selectById(mockId);
        Assertions.assertEquals("introspect基于oauth2协议的token认证", sysApi.getApiName());
    }
}
```

备注：
Mapper单元测试需要相关的数据源配置，用来进行数据库连接来进行sql语法及语句功能验证。配置文件路径${project.basedir}/src/test/resources/application-test.properties， 内容样例如下：

```properties
# 数据库连接地址
spring.datasource.url=jdbc:mysql://localhost:3306/sample-test?zeroDateTimeBehavior=convertToNull&useUnicode=true&characterEncoding=UTF-8&autoReconnect=true&serverTimezone=Asia/Shanghai
# 数据库用户名
spring.datasource.username=root
# 数据库密码
spring.datasource.password=root
```

### 2.Service类型单元测试

```java
package test.macula.cloud.system;

import dev.macula.cloud.system.mapper.*;
import dev.macula.cloud.system.pojo.entity.SysApi;
import dev.macula.cloud.system.service.SysApiService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {TestSysApiService.TestConfig.class})
public class TestSysApiService {
    @MockBean
    private SysApiMapper sysApiMapper;
    @MockBean
    private SysApiHeaderMapper sysApiHeaderMapper;
    @MockBean
    private SysApiRequestBodyMapper sysApiRequestBodyMapper;
    @MockBean
    private SysApiRequestParamMapper sysApiRequestParamMapper;
    @MockBean
    private SysApisTagsMapper sysApisTagsMapper;
    @MockBean
    private SysApiTagMapper sysApiTagMapper;

    @TestConfiguration
    @ComponentScan(value = {"dev.macula.cloud.system.service", "dev.macula.cloud.system.converter",
            "dev.macula.cloud.system.utils"},
            includeFilters = @ComponentScan.Filter(type = FilterType.REGEX, pattern = {".*(Api|SysApi).*$",
                    ".*(Swagger3DocParser|Swagger2DocParser|PostmanParser|ApiFoxParser).*$"}),
            useDefaultFilters = false)
    static class TestConfig { }

    @Autowired
    private SysApiService sysApiService;

    Long mockId = 1248L;

    @BeforeEach
    public void before(){
        SysApi mockSysApi = new SysApi();
        mockSysApi.setId(mockId);
        mockSysApi.setApiName("introspect");
        // 进行mock数据时需要考虑测试覆盖率, 测试覆盖率可以分为以下几个层次：
        // 语句覆盖率：测试用例覆盖了应用程序中的每个语句至少一次的百分比。
        // 分支覆盖率：测试用例覆盖了应用程序中的每个分支至少一次的百分比。
        // 函数覆盖率：测试用例覆盖了应用程序中的每个函数至少一次的百分比。
        // 行覆盖率：测试用例覆盖了应用程序中的每一行代码至少一次的百分比。
        // 在实际应用中，通常使用语句覆盖率和分支覆盖率这两种测试覆盖率指标来衡量测试的质量。
        // 由于当前使用的样例sysApiService.getById(mockId);
        // 具体代码为： getBaseMapper().selectById(id);
        // 所以只需mock一条数据就可达到语句覆盖率100%层次
        Mockito.when(sysApiMapper.selectById(mockId)).thenReturn(mockSysApi);
    }
    
    @Test
    public void testGetById(){
        SysApi sysApi = sysApiService.getById(mockId);
        Assertions.assertEquals("introspect", sysApi.getApiName());
    }
}
```

### 3.Controller类型单元测试

```java
package test.macula.cloud.system;

import com.alibaba.druid.spring.boot.autoconfigure.DruidDataSourceAutoConfigure;
import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import dev.macula.cloud.system.controller.SysApiController;
import dev.macula.cloud.system.pojo.entity.SysApiTag;
import dev.macula.cloud.system.query.ApiPageQuery;
import dev.macula.cloud.system.service.SysApiTagService;
import dev.macula.cloud.system.vo.apis.ApisVo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {TestSysApiController.TestSysApiControllerConfig.class, TestSysApiService.TestConfig.class,
        DruidDataSourceAutoConfigure.class, com.baomidou.mybatisplus.autoconfigure.MybatisPlusAutoConfiguration.class,
        dev.macula.boot.starter.mp.config.MyBatisPlusAutoConfiguration.class})
@MapperScan(basePackages = "dev.macula.cloud.system.mapper")
@TestPropertySource("classpath:application-test.properties")
public class TestSysApiController {
    @TestConfiguration
    @ComponentScan(basePackages = {"dev.macula.cloud.system.controller"}, includeFilters = {
                @ComponentScan.Filter(type= FilterType.REGEX, pattern = ".*SysApiController")},
            useDefaultFilters = false)
    static class TestSysApiControllerConfig{

    }

    @SpyBean
    private SysApiTagService apiTagService;

    @Autowired
    private SysApiController sysApiController;

    @BeforeEach
    public void mockServiceData(){
        List<SysApiTag> apiTags = new ArrayList<>();
        SysApiTag sysApiTag = new SysApiTag();
        sysApiTag.setId(2L);
        sysApiTag.setParentId(1L);
        sysApiTag.setName("children");
        apiTags.add(sysApiTag);
        sysApiTag = new SysApiTag();
        sysApiTag.setId(1L);
        sysApiTag.setParentId(0L);
        sysApiTag.setName("parent");
        apiTags.add(sysApiTag);
        // 添加数据库中apiName含introspect的mock数据，用于SysApiMapper真实数据库查询，将下面对象注释则查询不到任何对象
        sysApiTag = new SysApiTag();
        sysApiTag.setId(75L);
        sysApiTag.setParentId(2L);
        sysApiTag.setName("introspect_tag");
        apiTags.add(sysApiTag);

        // sysApiController.listApis执行中，其中会调用
        // apiTagService.list((Wrapper<T> queryWrapper)
        // apiTagService.recurTags(Long parentId, List<SysApiTag> tagList)
        // SysApiMapper.listApisPages(Page<SysApi> page, ApiPageQuery queryParams)
        // 该测试是对apiTagService.list((Wrapper<T> queryWrapper)打桩模拟生成数据，验证controller的执行结果是否正确
        Mockito.doReturn(apiTags).when(apiTagService).list(Mockito.any(Wrapper.class));
    }

    @Test
    public void testListApis(){
        ApiPageQuery apiPageQuery = new ApiPageQuery();
        apiPageQuery.setTagId(1L);
        apiPageQuery.setKeywords("introspect");
        IPage<ApisVo> res = sysApiController.listApis(apiPageQuery);
        // assertThat(res.getTotal(), equalTo(0L));
        assertThat(res.getTotal(), equalTo(1L));
        assertThat(res.getRecords().get(0).getApiName(), startsWith("introspect"));
    }
}
```

## 三、集成测试样例

在这个阶段，软件各层对象被组合在一起进行测试。

```java
注意：@SpringBootTest(classes = MaculaSystemApplication.class)启动SpringBoot的内嵌Tomcat容器，启动速度较慢。
```

### 1.基于整个容器的集成测试（无认证信息）

进行API测试时，理论上都需要经过认证鉴权，为了便于测试，可以通过配置新的Mock出来的 SecurityFilterChain，跳过认证鉴权。

```java
package test.macula.cloud.system;

import dev.macula.cloud.system.MaculaSystemApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.core.Is.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ActiveProfiles("dev")
@SpringBootTest(classes = MaculaSystemApplication.class)
@AutoConfigureMockMvc
public class TestSysApiRest {
    // macula默认使用macula-boot-starter-security进行相关路径权限验证，为方便进行接口测试，替换默认的SecurityFilterChain，实现所有接口支持无权限访问
    @MockBean
    private SecurityFilterChain securityFilterChain;
    
    @Autowired
    private MockMvc mvc;

    @Test
    public void testListApisThenStatus200AndReturnOneData() throws Exception{
        mvc.perform(get("/api/v1/doc?pageNo=1&pageSize=1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success", is(true)))
                .andDo(print());
    }
}
```

### 2.基于整个容器的集成测试（有认证信息）

进行API测试时，为通过完整的认证鉴权环节，需要准备好接入认证中心需要的clientId和clientSecret，以及相应的用户账号和密码。

```java
package test.macula.cloud.system;

import com.alibaba.excel.util.StringUtils;
import com.alibaba.fastjson.JSONObject;
import com.nimbusds.jwt.JWTClaimNames;
import dev.macula.boot.constants.SecurityConstants;
import dev.macula.cloud.system.MaculaSystemApplication;
import lombok.Data;
import lombok.ToString;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.core.Is.is;

@ActiveProfiles("dev")
@AutoConfigureMockMvc
@SpringBootTest(classes = MaculaSystemApplication.class)
public class TestSysUserRest {
    // 客户端管理中的登录客户端id
    private static final String CLIENT_ID = "cbs_client_test";
    // 客户端管理中的登录客户端id对应的客户端密码
    private static final String CLIENT_SECRET = "cbs_client_test";
    // 登录用户
    private static final String USER_NAME = "228324808";
    // 登录用户密码
    private static final String PASSWORD = "136258";
    // 登录路径（iam默认：http://localhost:9010/oauth2/token）
    private static final String OAUTH_URL = "http://localhost:9010/oauth2/token";
    // 真实登录请求路径模板
    private static final String GET_TOKEN_URI_TEMPLATE = "%s?grant_type=password&username=%s&password=%s&client_id=%s&client_secret=%s";
    // token认证路径(iam默认：http://localhost:9010/oauth2/introspect)
    private static final String OAUTH_VERIFY_URL = "http://localhost:9010/oauth2/introspect";
    // 真实token认证请求路径模板
    private static final String OAUTH_VERIFY_URI_TEMPLATE = "%s?token=%s";
    private static final RestTemplate REST_TEMPLATE = new RestTemplate();
    // 集成测试请求头Authorization的 token值，配置则直接使用来进行接口访问，不配置则通过上文的USER_NAME+PASSWORD进行登录获取
    private static String tokenValue;

    @Autowired
    private MockMvc mvc;

    @MockBean
    private JwtDecoder jwtDecoder;

    @BeforeAll
    public static void setUp(){
        // 不是所有类型的token都可以通过rest请求实时获取， 比如： 授权码认证
        if(StringUtils.isNotBlank(tokenValue)){
            return;
        }
        String getTokenUri = String.format(GET_TOKEN_URI_TEMPLATE, OAUTH_URL, USER_NAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);
        TokenVo tokenVo = REST_TEMPLATE.postForObject(getTokenUri, null, TokenVo.class);
        Assertions.assertNotNull(tokenVo, "获取token请求失败");
        Assertions.assertNotNull(tokenVo.getAccess_token(), "获取token_value失败");
        tokenValue = tokenVo.getAccess_token();
    }

    @BeforeEach
    public void handlerOauthOpaqueToken(){
        String getUserInfoUri = String.format(OAUTH_VERIFY_URI_TEMPLATE, OAUTH_VERIFY_URL, tokenValue);
        // 添加basic认证请求头
        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.setBasicAuth(CLIENT_ID, CLIENT_SECRET);
        HttpEntity requestEntity = new HttpEntity(requestHeaders);
        TokenUserInfoVo userInfoVo = REST_TEMPLATE.postForObject(getUserInfoUri, requestEntity, TokenUserInfoVo.class);
        Assertions.assertTrue(userInfoVo != null && userInfoVo.isActive(), "token已过期");
        // jwt 生成请参数当前macula上下文的AddJwtGlobalFilter.generateJwtToken,当前样例使用的版本是5.0.3.RELEASE
        // 注意仿照的是jwt对象内信息，无须使用jwtEncoder
        Jwt jwt = getCurVersionGwJwt(userInfoVo);
        Mockito.when(jwtDecoder.decode(tokenValue)).thenReturn(jwt);
    }

    @Test
    public void givenGetLoginUserInfothenStatus200()
            throws Exception {
        mvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + tokenValue)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.data.username", is(USER_NAME)));
    }


    private Jwt getCurVersionGwJwt(TokenUserInfoVo userInfoVo){
        Map<String, Object> claimsMap = JSONObject.parseObject(JSONObject.toJSONString(userInfoVo));
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        OAuth2IntrospectionAuthenticatedPrincipal principal = new OAuth2IntrospectionAuthenticatedPrincipal(claimsMap, authorities);

        // 取自源码macula-boot-starter-cloud-gateway中AddJwtGlobalFilter.generateJwtToken
        JwtClaimsSet.Builder jwtClaimBuilder = JwtClaimsSet.builder();
        // copy oauth2服务器返回的attribute
        principal.getAttributes().forEach(jwtClaimBuilder::claim);

        Instant issuedAt = Instant.now();
        // 处理时间
        jwtClaimBuilder.expiresAt(issuedAt.plus(30, ChronoUnit.DAYS));
        jwtClaimBuilder.issuedAt(issuedAt);

        // 如果缺少jti、deptId、dataScope、nickname，设置默认值
        if (!principal.getAttributes().containsKey(JWTClaimNames.JWT_ID)) {
            jwtClaimBuilder.id(UUID.randomUUID().toString());
        }
        if (!principal.getAttributes().containsKey(SecurityConstants.JWT_NICKNAME_KEY)) {
            jwtClaimBuilder.claim(SecurityConstants.JWT_NICKNAME_KEY, principal.getName());
        }
        if (!principal.getAttributes().containsKey(SecurityConstants.JWT_DEPTID_KEY)) {
            jwtClaimBuilder.claim(SecurityConstants.JWT_DEPTID_KEY, SecurityConstants.ROOT_NODE_ID);
        }
        if (!principal.getAttributes().containsKey(SecurityConstants.JWT_DATASCOPE_KEY)) {
            jwtClaimBuilder.claim(SecurityConstants.JWT_DATASCOPE_KEY, 0);
        }
        // 如果principal没有issue，需要设置jwt的issue
        //if (!principal.getAttributes().containsKey(JWTClaimNames.ISSUER)) {
        //    jwtClaimBuilder.claim(JWTClaimNames.ISSUER, issuerUri);
        //}
        // 外部定制claims
        //jwtClaimsCustomizer.customize(jwtClaimBuilder);

        JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.RS256;
        JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);

        JwtClaimsSet claims = jwtClaimBuilder.build();
        JwsHeader jwsHeader = jwsHeaderBuilder.build();
        return new Jwt(tokenValue, claims.getIssuedAt(), claims.getExpiresAt(), jwsHeader.getHeaders(), claims.getClaims());
    }

    @Data
    @ToString
    static class TokenVo {
        private String access_token;
        private String token_type;
        private String refresh_token;
        private Integer expires_in;
    }

    @Data
    @ToString
    static class TokenUserInfoVo{
        private String sub;
        private boolean active;
        private String userType;
        private long exp;
        private String jti;
        private List<String> authorities;
    }
}
```