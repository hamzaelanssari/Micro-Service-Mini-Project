package org.sid.billingservice;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;import lombok.Data; import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.hateoas.PagedModel;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.persistence.*;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import javax.validation.Valid;
import java.io.IOException;
import java.util.*;


@SpringBootApplication
@EnableFeignClients
public class BillingServiceApplication {


    public static void main(String[] args) {
        SpringApplication.run(BillingServiceApplication.class, args);
    }
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner start(AccountService accountService,BillRepository billRepository, ProductItemRepository productItemRepository, InventoryServiceClient inventoryServiceClient, CustomerServiceClient customerServiceClient) {
        return args -> {
            Bill bill = new Bill();
            bill.setBillingDate(new Date());
            Customer customer = customerServiceClient.findCustomerById(1L);
            System.out.println(customer.toString());
            bill.setCustomerID(customer.getId());
            billRepository.save(bill);
            inventoryServiceClient.findAll().getContent().forEach(p -> {
                productItemRepository.save(new ProductItem(null, null, p.getId(), p.getPrice(), (int) (1 + Math.random() * 1000), bill));
            });
            accountService.saveRole(new AppRole(null,"USER"));
            accountService.saveRole(new AppRole(null,"ADMIN"));
            accountService.saveUser(new AppUser(null,"user","1234", null));
            accountService.saveUser(new AppUser(null,"admin","1234", null));
            accountService.addRoleToUser("user", "USER");
            accountService.addRoleToUser("admin", "USER");
            accountService.addRoleToUser("admin", "ADMIN");
        };
    }
}


@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
class Bill{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; private Date billingDate;
    @Transient
    @OneToMany(mappedBy = "bill")
    private Collection<ProductItem> productItems;
    @Transient private Customer customer;
    private long customerID;
}
@RepositoryRestResource
interface BillRepository extends JpaRepository<Bill,Long> {}

@Entity @Data @NoArgsConstructor @AllArgsConstructor
class ProductItem{
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Transient
    private Product product; private long productID;
    private double price; private double quantity;
    @ManyToOne
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private Bill bill;
}
@RepositoryRestResource
interface ProductItemRepository extends
        JpaRepository<ProductItem,Long>{
    List<ProductItem> findByBillId(Long billID);
}


@Data
class Product{
    private Long id; private String name; private double price;
}

@Data
class Customer{
    private Long id; private String name; private String email;
}

@FeignClient(name="inventory-service")
interface InventoryServiceClient{
    @GetMapping("/products/{id}?projection=FullProduct")
    Product findProductById(@PathVariable("id") Long id);
    @GetMapping("/products?projection=FullProduct")
    PagedModel<Product> findAll();
}

@FeignClient(name="customer-service")
interface CustomerServiceClient{
    @GetMapping("/customers/{id}?projection=FullCustomer")
    Customer findCustomerById(@PathVariable("id") Long id);
}

@RestController
class BillRestController{
    @Autowired private BillRepository billRepository;
    @Autowired private ProductItemRepository productItemRepository;
    @Autowired private CustomerServiceClient customerServiceClient;
    @Autowired private InventoryServiceClient inventoryServiceClient;

    @GetMapping("/bills")
    public List<Bill> listTasks(){
        return billRepository.findAll();
    }
    @PostMapping("/bills")
    public Bill save(@RequestBody Bill task){
        return billRepository.save(task);
    }

    @GetMapping("/bills/Full/{id}")
    Bill getBill(@PathVariable(name="id") Long id){
        Bill bill=billRepository.findById(id).get();
        bill.setCustomer(customerServiceClient.findCustomerById(bill.getCustomerID()));
        bill.setProductItems(productItemRepository.findByBillId(id));
        bill.getProductItems().forEach(pi->{
            pi.setProduct(inventoryServiceClient.findProductById(pi.getProductID()));
        });
        return bill; }
    @RequestMapping(value = "/admin/bills/delete",method= RequestMethod.GET)
    public RedirectView delete(Model model, @RequestParam(name="id",required = true)Long id){
        billRepository.deleteById(id);
        return new RedirectView("/bills");
    }

    @RequestMapping(value="/admin/form",method= RequestMethod.GET)
    public ModelAndView form(Model model, @RequestParam(name="id",defaultValue = "0") Long id){
        Bill p = (billRepository.existsById(id))? billRepository.getOne(id):new Bill();
        model.addAttribute("bill", p);
        return new ModelAndView("form");
    }
    @RequestMapping(value="/admin/save",method=RequestMethod.POST)
    public ModelAndView save(Model model, @Valid Bill p, BindingResult bindingResult){
        if(bindingResult.hasErrors()) return new ModelAndView("form");
        billRepository.save(p);
        model.addAttribute("bill", p);
        return new ModelAndView("confirmation");
    }
    @RequestMapping(value="/403",method= RequestMethod.GET)
    public ModelAndView error(){
        return new ModelAndView("error/403");
    }
}



/* Security */

@Entity
@Data @AllArgsConstructor @NoArgsConstructor
class AppRole {
    @Id @GeneratedValue
    private Long id;
    private String role;
}


@Entity
@Data @AllArgsConstructor @NoArgsConstructor
class AppUser {
    @Id @GeneratedValue
    private Long id;
    private String username;
    private String password;
    @ManyToMany(fetch=FetchType.EAGER)
    private Collection<AppRole> roles=new ArrayList<>();
}

interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
interface AppRoleRepository extends JpaRepository<AppRole,Long>{
    AppRole findByRole(String role);
}
interface AccountService {
    AppUser saveUser(AppUser u);
    AppRole saveRole(AppRole r);
    AppUser findUserByUsername(String username);
    void addRoleToUser(String username,String role);
}

@Service
@Transactional
class AccountServiceImpl implements AccountService {
    @Autowired
    private AppUserRepository userRepository;
    @Autowired
    private AppRoleRepository roleRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public AppUser saveUser(AppUser u) {
        u.setPassword(bCryptPasswordEncoder.encode(u.getPassword()));
        return userRepository.save(u);
    }
    @Override
    public AppRole saveRole(AppRole r) {
        return roleRepository.save(r);
    }
    @Override
    public AppUser findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser user=userRepository.findByUsername(username);
        AppRole role=roleRepository.findByRole(roleName);
        user.getRoles().add(role);
    }
}

@Data @AllArgsConstructor @NoArgsConstructor
class RegistrationForm {
    private String username;
    private String password;
    private String repassword;
}

@RestController
class UserController {
    @Autowired
    private AccountService accountService;
    @PostMapping("/users")
    public AppUser signUp(@RequestBody RegistrationForm data) {
        String username=data.getUsername();
        AppUser user=accountService.findUserByUsername(username);
        if(user!=null) throw new RuntimeException("This user already exists, Try with an other username");
                String password=data.getPassword(); String repassword=data.getRepassword();
        if(!password.equals(repassword))
            throw new RuntimeException("You must confirm your password");
        AppUser u=new AppUser(); u.setUsername(username); u.setPassword(password);
        accountService.saveUser(u);
        accountService.addRoleToUser(username, "USER");
        return (u);
    }
}
@Configuration
@EnableWebSecurity
class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
// don't create session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/users/**", "/login/**")
                .permitAll()
                .antMatchers(HttpMethod.POST, "/bills/**").hasAuthority("ADMIN")
                .anyRequest().authenticated()
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .addFilterBefore(new JWTAuthorizationFilter(),
                        UsernamePasswordAuthenticationFilter.class);
    }
}
class SecurityConstants {
    public static final String SECRET = "elanssarihamza@gmail.com";
    public static final long EXPIRATION_TIME = 864_000_000;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
}

@Service
class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private AccountService accountService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser u=accountService.findUserByUsername(username);
        if(u==null) throw new UsernameNotFoundException(username);
        Collection<GrantedAuthority> authorities=new ArrayList<>();
        u.getRoles().forEach(r->{
            authorities.add(new SimpleGrantedAuthority(r.getRole()));
        });
        return new User(u.getUsername(), u.getPassword(), authorities);
    }
}

class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        super();
        this.authenticationManager = authenticationManager;
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        AppUser user=null;
        try {
            user = new ObjectMapper().readValue(request.getInputStream(), AppUser.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(),
                        user.getPassword()
                ));
    }
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse
            response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        User springUser=(User)authResult.getPrincipal();
        String jwtToken= Jwts.builder()
                .setSubject(springUser.getUsername())
                .setExpiration(new
                        Date(System.currentTimeMillis()+SecurityConstants.EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SecurityConstants.SECRET)
                .claim("roles", springUser.getAuthorities())
                .compact();
        response.addHeader(SecurityConstants.HEADER_STRING,
                SecurityConstants.TOKEN_PREFIX+jwtToken);
    }
}

class JWTAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain)
            throws IOException, ServletException {
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Allow-Headers", "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-RequestHeaders,authorization");
                response.addHeader("Access-Control-Expose-Headers", "Access-Control-Allow-Origin, Access-Control-Allow-Credentials, authorization");
        if(request.getMethod().equals("OPTIONS")){
            response.setStatus(HttpServletResponse.SC_OK);
        }
        else {
            String jwtToken=request.getHeader(SecurityConstants.HEADER_STRING);
            if(jwtToken==null || !jwtToken.startsWith(SecurityConstants.TOKEN_PREFIX)) {
                chain.doFilter(request, response); return;
            }
            Claims claims=Jwts.parser()
                    .setSigningKey(SecurityConstants.SECRET)
                    .parseClaimsJws(jwtToken.replace(SecurityConstants.TOKEN_PREFIX,""))
                    .getBody();
            String username=claims.getSubject();
            ArrayList<Map<String, String>> roles=(ArrayList<Map<String, String>>)
                    claims.get("roles");
            Collection<GrantedAuthority> authorities=new ArrayList<>();
            roles.forEach(r->{
                authorities.add(new SimpleGrantedAuthority(r.get("authority")));
            });
            UsernamePasswordAuthenticationToken authenticationToken=
                    new UsernamePasswordAuthenticationToken(username, null,authorities);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            chain.doFilter(request, response);
        }
    }}