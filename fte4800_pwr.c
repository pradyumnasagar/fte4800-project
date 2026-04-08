#include <linux/module.h>
#include <linux/gpio/consumer.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>
#include <linux/delay.h>
#include <linux/gpio.h>

static struct gpio_desc *reset_gpio;
static struct device *spi_dev;

static int __init fte4800_pwr_init(void)
{
    struct gpio_desc *avdd_desc;
    int base = 512;
    int avdd_num = base + 23;
    
    spi_dev = bus_find_device_by_name(&spi_bus_type, NULL, "spi-FTE4800:00");
    if (!spi_dev) {
        printk(KERN_ERR "FTE4800: SPI device not found\n");
        return -ENODEV;
    }

    // 1. Force AVDD High (Pin 23) via global kernel GPIO number
    avdd_desc = gpio_to_desc(avdd_num);
    if (avdd_desc) {
        printk(KERN_INFO "FTE4800: Found AVDD descriptor (GPIO %d). Forcing HIGH...\n", avdd_num);
        gpiod_set_raw_value(avdd_desc, 1);
    } else {
        printk(KERN_WARNING "FTE4800: Could not get AVDD descriptor for GPIO %d\n", avdd_num);
    }
    msleep(50); // wait for power to stabilize

    // 2. Pulse RESET (index 0)
    reset_gpio = gpiod_get_index(spi_dev, NULL, 0, GPIOD_OUT_LOW);
    if (!IS_ERR(reset_gpio)) {
        printk(KERN_INFO "FTE4800: Claimed RESET index 0. Asserting LOW...\n");
        msleep(50);
        printk(KERN_INFO "FTE4800: Releasing RESET (HIGH)...\n");
        gpiod_set_value(reset_gpio, 1);
        msleep(100);
        printk(KERN_INFO "FTE4800: Hardware reset pulse complete!\n");
    } else {
        printk(KERN_ERR "FTE4800: Failed to get RESET index 0: %ld\n", PTR_ERR(reset_gpio));
    }
    
    return 0;
}

static void __exit fte4800_pwr_exit(void)
{
    if (!IS_ERR_OR_NULL(reset_gpio)) {
        gpiod_put(reset_gpio);
    }
    if (spi_dev) {
        put_device(spi_dev);
    }
    printk(KERN_INFO "FTE4800: Power module exited\n");
}

module_init(fte4800_pwr_init);
module_exit(fte4800_pwr_exit);
MODULE_LICENSE("GPL");
