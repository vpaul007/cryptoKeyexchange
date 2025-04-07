import java.io.Serializable;

public class Product implements Serializable {
    private String name;
    private String description;
    private int quantity;

    public Product(String name, String description, int quantity) {
        this.name = name;
        this.description = description;
        this.quantity = quantity;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public int getQuantity() {
        return quantity;
    }

    @Override
    public String toString() {
        return "Product{name='" + name + "', description='" + description + "', quantity=" + quantity + "}";
    }
}
