<?php
/**
 * Other.
 *
 * @package     consultstreet
 */

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( 'ConsultStreet_Other_General_Option' ) ) :

	/**
	 * Other..
	 */
	class ConsultStreet_Other_General_Option extends ConsultStreet_Customize_Base_Option {

		public function elements() {

			return array(
			
			    'consultstreet_header_banner_image_heading'     => array(
					'setting' => array(),
					'control' => array(
						'type'    => 'heading',
				   		'priority'        => 53,
						'label'   => esc_html__( 'Magazine Header Settings', 'consultstreet' ),
						'section' => 'title_tagline',
					),
				),
				
				'consultstreet_header_banner_image_disabled'            => array(
					'setting' => array(
						'default'           => true,
						'sanitize_callback' => array( 'ConsultStreet_Customizer_Sanitize', 'sanitize_checkbox' ),
					),
					'control' => array(
						'type'     => 'toggle',
						'priority' => 54,
						'label'    => esc_html__( 'Enable/Disable Banner Image', 'consultstreet' ),
						'section'  => 'title_tagline',
					),
				),
				
				'consultstreet_header_banner_image_link' => array(
					'setting' => array(
						'default'           => '#',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'control' => array(
						'type'            => 'text',
						'priority'        => 56,
						'is_default_type' => true,
						'label'           => esc_html__( 'Banner Image Link', 'consultstreet' ),
						'section'         => 'title_tagline',
					),
				),
				
				'consultstreet_header_banner_open_new_tab_disabled'            => array(
					'setting' => array(
						'default'           => true,
						'sanitize_callback' => array( 'ConsultStreet_Customizer_Sanitize', 'sanitize_checkbox' ),
					),
					'control' => array(
						'type'     => 'toggle',
						'priority' => 57,
						'label'    => esc_html__( 'Open New Tab Enable/Disable', 'consultstreet' ),
						'section'  => 'title_tagline',
					),
				),
				
				'consultstreet_magazine_header_menu_alignment'     => array(
						'setting' => array(
							'default'           => 'm-left-auto',
							'sanitize_callback' => array( 'ConsultStreet_Customizer_Sanitize', 'sanitize_radio' ),
						),
						'control' => array(
							'type'            => 'radio',
							'priority'        => 58,
							'is_default_type' => true,
							'label'           => esc_html__( 'Magazine Header Menu Alignment', 'consultstreet' ),
							'section'         => 'title_tagline',
							'choices'         => array(
								'm-left-auto'  => esc_html__( 'Left', 'consultstreet' ),
								'm-right-left-auto' => esc_html__( 'Center', 'consultstreet' ),
							),
						),
			    ),
				
					
				'consultstreet_custom_logo_size' => array(
					'setting' => array(
						'default'           => array(
							'slider' => 257,
							'suffix' => 'px',
						),
						'sanitize_callback' => array( 'ConsultStreet_Customizer_Sanitize', 'sanitize_slider' ),
					),
					'control' => array(
						'type'        => 'slider',
						'priority'    => 52,
						'label'       => esc_html__( 'Logo Width', 'consultstreet' ),
						'section'     => 'title_tagline',
						'input_attrs' => array(
							'min'  => 0,
							'max'  => 600,
							'step' => 3,
						),
					),
				),
				

			);

		}

	}

	new ConsultStreet_Other_General_Option();

endif;
