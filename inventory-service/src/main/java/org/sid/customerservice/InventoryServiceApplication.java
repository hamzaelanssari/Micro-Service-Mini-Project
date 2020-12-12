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
public class InventoryServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(InventoryServiceApplication.class, args);
    }
    @Bean
    CommandLineRunner start(ProductRepository productRepository){
        return args -> {
            productRepository.save(new Product(null,"Computer Desk Top HP",900));
            productRepository.save(new Product(null,"Printer Epson",80));
            productRepository.save(new Product(null,"MacBook Pro Lap Top",1800));
            productRepository.findAll().forEach(System.out::println);
        };
    }

}

@Entity @Data @NoArgsConstructor @AllArgsConstructor @ToString
class Product{
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; private String name;private double price;
}


@RepositoryRestResource
interface ProductRepository extends JpaRepository<Product,Long> {
    @RestResource(path = "/byName")
    Page<Product> findByNameContains(@Param("kw") String name, Pageable pageable);
}


@Projection(name = "FullProduct",types = Product.class)
interface FullCustomerProjection extends Projection{
    Long getId();
    String getName();
    String getPrice();
}

@Projection(name = "NameProduct",types = Product.class)
interface NameCustomerProjection extends Projection{
    String getName();
}