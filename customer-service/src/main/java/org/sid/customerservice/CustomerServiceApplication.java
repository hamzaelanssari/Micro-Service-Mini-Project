package org.sid.customerservice;

import lombok.AllArgsConstructor;
import lombok.Data; import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.data.rest.core.config.Projection;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@SpringBootApplication
public class CustomerServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(CustomerServiceApplication.class, args);
    }
    @Bean
    CommandLineRunner start(CustomerRepository customerRepository){
        return args -> {
            customerRepository.save(new Customer(null,"Enset1","contact@enset-media.ma"));
            customerRepository.save(new Customer(null,"FSTM1","contact@fstm.ma"));
            customerRepository.save(new Customer(null,"ENSAM1","contact@ensam.ma"));

            customerRepository.save(new Customer(null,"Enset2","contact@enset-media.ma"));
            customerRepository.save(new Customer(null,"FSTM2","contact@fstm.ma"));
            customerRepository.save(new Customer(null,"ENSAM2","contact@ensam.ma"));

            customerRepository.save(new Customer(null,"Enset3","contact@enset-media.ma"));
            customerRepository.save(new Customer(null,"FSTM3","contact@fstm.ma"));
            customerRepository.save(new Customer(null,"ENSAM3","contact@ensam.ma"));

            customerRepository.save(new Customer(null,"Enset3","contact@enset-media.ma"));
            customerRepository.save(new Customer(null,"FSTM3","contact@fstm.ma"));
            customerRepository.save(new Customer(null,"ENSAM3","contact@ensam.ma"));

            customerRepository.save(new Customer(null,"Enset4","contact@enset-media.ma"));
            customerRepository.save(new Customer(null,"FSTM4","contact@fstm.ma"));
            customerRepository.save(new Customer(null,"ENSAM4","contact@ensam.ma"));

            customerRepository.save(new Customer(null,"Enset5","contact@enset-media.ma"));
            customerRepository.save(new Customer(null,"FSTM5","contact@fstm.ma"));
            customerRepository.save(new Customer(null,"ENSAM5","contact@ensam.ma"));

            customerRepository.findAll().forEach(System.out::println);
        };
    }

}

@Entity @Data @NoArgsConstructor @AllArgsConstructor @ToString
class Customer{
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; private String name; private String email;
}

@RepositoryRestResource
interface CustomerRepository extends JpaRepository<Customer,Long> {
    @RestResource(path = "/byName")
    Page<Customer> findByNameContains(@Param("kw") String name, Pageable pageable);
}
@Projection(name = "FullCustomer",types = Customer.class)
interface FullCustomerProjection extends Projection{
    Long getId();
    String getName();
    String getEmail();
}

@Projection(name = "NameCustomer",types = Customer.class)
interface NameCustomerProjection extends Projection{
    String getName();
}